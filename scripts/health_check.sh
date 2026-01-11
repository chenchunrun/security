#!/bin/bash
# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################################################################################
# Security Triage System - Health Check Script
################################################################################
#
# This script performs comprehensive health checks on all services
# in the Security Triage System.
#
# Usage:
#   ./health_check.sh [options]
#
# Options:
#   -s, --service NAME    Check specific service only
#   -w, --watch           Continuously monitor health (refresh every 5s)
#   -j, --json            Output results in JSON format
#   -v, --verbose         Show detailed health information
#   -h, --help            Show this help message
#
# Examples:
#   ./health_check.sh                    # Check all services
#   ./health_check.sh -s ai-triage-agent # Check specific service
#   ./health_check.sh -w                 # Watch mode (continuous)
#   ./health_check.sh -j                 # JSON output for monitoring
#
################################################################################

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
TARGET_SERVICE=""
WATCH_MODE=false
JSON_OUTPUT=false
VERBOSE=false

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service health status
declare -A SERVICE_STATUS
declare -A SERVICE_PORTS
declare -A HEALTH_ENDPOINTS

# Initialize service configurations
init_service_config() {
    # Infrastructure services
    SERVICE_PORTS["postgres"]="5432"
    SERVICE_PORTS["redis"]="6379"
    SERVICE_PORTS["rabbitmq"]="5672"
    SERVICE_PORTS["chromadb"]="8001"

    # Application services
    SERVICE_PORTS["alert-ingestor"]="9001"
    SERVICE_PORTS["alert-normalizer"]="9002"
    SERVICE_PORTS["context-collector"]="9003"
    SERVICE_PORTS["threat-intel-aggregator"]="9004"
    SERVICE_PORTS["llm-router"]="9005"
    SERVICE_PORTS["ai-triage-agent"]="9006"
    SERVICE_PORTS["similarity-search"]="9007"
    SERVICE_PORTS["workflow-engine"]="9008"
    SERVICE_PORTS["automation-orchestrator"]="9009"
    SERVICE_PORTS["configuration-service"]="9010"
    SERVICE_PORTS["data-analytics"]="9011"
    SERVICE_PORTS["reporting-service"]="9012"
    SERVICE_PORTS["notification-service"]="9013"
    SERVICE_PORTS["monitoring-metrics"]="9014"
    SERVICE_PORTS["web-dashboard"]="9015"
    SERVICE_PORTS["api-gateway"]="8000"

    # Health endpoints
    HEALTH_ENDPOINTS["api-gateway"]="http://localhost:8000/health"
    HEALTH_ENDPOINTS["alert-ingestor"]="http://localhost:9001/health"
    HEALTH_ENDPOINTS["alert-normalizer"]="http://localhost:9002/health"
    HEALTH_ENDPOINTS["context-collector"]="http://localhost:9003/health"
    HEALTH_ENDPOINTS["threat-intel-aggregator"]="http://localhost:9004/health"
    HEALTH_ENDPOINTS["llm-router"]="http://localhost:9005/health"
    HEALTH_ENDPOINTS["ai-triage-agent"]="http://localhost:9006/health"
}

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}===>${NC} $1"
}

show_help() {
    cat << EOF
Usage: $(basename "$0") [options]

Perform health checks on Security Triage System services.

Options:
  -s, --service NAME    Check specific service only
  -w, --watch           Continuously monitor health (refresh every 5s)
  -j, --json            Output results in JSON format
  -v, --verbose         Show detailed health information
  -h, --help            Show this help message

Available Services:
  Infrastructure: postgres, redis, rabbitmq, chromadb
  Core Pipeline: alert-ingestor, alert-normalizer, context-collector,
                 threat-intel-aggregator, llm-router, ai-triage-agent
  Support Services: api-gateway, web-dashboard, similarity-search, etc.

Examples:
  # Check all services
  $(basename "$0")

  # Check specific service
  $(basename "$0") -s ai-triage-agent

  # Watch mode (continuous monitoring)
  $(basename "$0") -w

  # JSON output for monitoring systems
  $(basename "$0") -j

EOF
}

check_docker_container() {
    local service=$1
    local container_name="security-triage-${service}"

    # Check if container exists
    if ! docker ps -a --format '{{{{.Names}}}}' | grep -q "^${container_name}$"; then
        SERVICE_STATUS[$service]="not_found"
        return 1
    fi

    # Check if container is running
    if ! docker ps --format '{{{{.Names}}}}' | grep -q "^${container_name}$"; then
        SERVICE_STATUS[$service]="stopped"
        return 1
    fi

    # Check container health status
    local health_status=$(docker inspect --format '{{{{.State.Health.Status}}}}' "$container_name" 2>/dev/null || echo "unknown")

    case "$health_status" in
        healthy)
            SERVICE_STATUS[$service]="healthy"
            return 0
            ;;
        unhealthy)
            SERVICE_STATUS[$service]="unhealthy"
            return 1
            ;;
        starting)
            SERVICE_STATUS[$service]="starting"
            return 1
            ;;
        *)
            SERVICE_STATUS[$service]="running"
            return 0
            ;;
    esac
}

check_http_endpoint() {
    local service=$1
    local endpoint="${HEALTH_ENDPOINTS[$service]:-}"

    if [ -z "$endpoint" ]; then
        return 0  # No endpoint configured, skip
    fi

    # Check HTTP endpoint
    if command -v curl &> /dev/null; then
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint" --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")

        if [ "$response" = "200" ]; then
            return 0
        else
            SERVICE_STATUS[$service]="http_error_$response"
            return 1
        fi
    elif command -v wget &> /dev/null; then
        if wget -q --spider --timeout=5 "$endpoint" 2>/dev/null; then
            return 0
        else
            SERVICE_STATUS[$service]="http_unreachable"
            return 1
        fi
    fi

    return 0  # No curl/wget available, skip
}

check_port_connectivity() {
    local service=$1
    local port="${SERVICE_PORTS[$service]:-}"

    if [ -z "$port" ]; then
        return 0  # No port configured
    fi

    if command -v nc &> /dev/null; then
        if nc -z localhost "$port" 2>/dev/null; then
            return 0
        else
            return 1
        fi
    elif command -v bash &> /dev/null; then
        if timeout 1 bash -c "echo > /dev/tcp/localhost/$port" 2>/dev/null; then
            return 0
        else
            return 1
        fi
    fi

    return 0  # No tools available, skip
}

check_service_health() {
    local service=$1
    local verbose=$2

    # Check Docker container
    check_docker_container "$service"

    # If container is healthy, check HTTP endpoint (if configured)
    if [ "${SERVICE_STATUS[$service]}" = "healthy" ] || [ "${SERVICE_STATUS[$service]}" = "running" ]; then
        check_http_endpoint "$service"
        check_port_connectivity "$service"
    fi

    # Output result
    local status="${SERVICE_STATUS[$service]}"
    local status_icon="✓"
    local status_color="${GREEN}"

    case "$status" in
        healthy)
            status_icon="✓"
            status_color="${GREEN}"
            ;;
        running|starting)
            status_icon="⧖"
            status_color="${YELLOW}"
            ;;
        *)
            status_icon="✗"
            status_color="${RED}"
            ;;
    esac

    if [ "$JSON_OUTPUT" = false ]; then
        echo -e "${status_color}${status_icon}${NC} ${service}: ${status}"

        if [ "$verbose" = true ]; then
            local port="${SERVICE_PORTS[$service]:-N/A}"
            local endpoint="${HEALTH_ENDPOINTS[$service]:-N/A}"

            echo "  Port: ${port}"
            echo "  Health Endpoint: ${endpoint}"
            echo "  Container: security-triage-${service}"

            # Show container details
            local container_name="security-triage-${service}"
            if docker ps --format '{{{{.Names}}}}' | grep -q "^${container_name}$"; then
                local uptime=$(docker exec "$container_name" uptime -p 2>/dev/null || echo "N/A")
                echo "  Uptime: ${uptime}"
            fi
            echo ""
        fi
    fi
}

check_all_services() {
    local services=(
        "postgres"
        "redis"
        "rabbitmq"
        "chromadb"
        "alert-ingestor"
        "alert-normalizer"
        "context-collector"
        "threat-intel-aggregator"
        "llm-router"
        "ai-triage-agent"
        "api-gateway"
        "web-dashboard"
    )

    for service in "${services[@]}"; do
        if [ -z "$TARGET_SERVICE" ] || [ "$TARGET_SERVICE" = "$service" ]; then
            check_service_health "$service" "$VERBOSE"
        fi
    done
}

output_json() {
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"services\": {"

    local first=true
    for service in "${!SERVICE_STATUS[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi

        local status="${SERVICE_STATUS[$service]}"
        local port="${SERVICE_PORTS[$service]:-null}"
        local endpoint="${HEALTH_ENDPOINTS[$service]:-null}"

        echo -n "    \"${service}\": {
      \"status\": \"${status}\",
      \"port\": ${port},
      \"health_endpoint\": \"${endpoint}\"
    }"
    done

    echo ""
    echo "  }"
    echo "}"
}

output_summary() {
    local healthy=0
    local unhealthy=0
    local total=0

    for status in "${SERVICE_STATUS[@]}"; do
        total=$((total + 1))
        if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
            healthy=$((healthy + 1))
        else
            unhealthy=$((unhealthy + 1))
        fi
    done

    echo ""
    echo "=============================================================================="
    echo "Health Check Summary"
    echo "=============================================================================="
    echo "Total Services: $total"
    echo -e "${GREEN}Healthy: $healthy${NC}"
    echo -e "${RED}Unhealthy: $unhealthy${NC}"
    echo "Health Percentage: $(( (healthy * 100) / total ))%"
    echo "=============================================================================="
}

################################################################################
# Main Function
################################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--service)
                TARGET_SERVICE="$2"
                shift 2
                ;;
            -w|--watch)
                WATCH_MODE=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Initialize service configuration
    init_service_config

    # Watch mode
    if [ "$WATCH_MODE" = true ]; then
        while true; do
            clear
            echo "=============================================================================="
            echo "Security Triage System - Health Check (Watch Mode)"
            echo "=============================================================================="
            echo "Last Update: $(date)"
            echo "Press Ctrl+C to exit"
            echo "=============================================================================="
            echo ""

            # Clear previous status
            SERVICE_STATUS=()
            check_all_services

            if [ "$JSON_OUTPUT" = false ]; then
                output_summary
            fi

            sleep 5
        done
    fi

    # Single run mode
    if [ "$JSON_OUTPUT" = false ]; then
        echo "=============================================================================="
        echo "Security Triage System - Health Check"
        echo "=============================================================================="
        echo "Timestamp: $(date)"
        echo "=============================================================================="
        echo ""
    fi

    check_all_services

    if [ "$JSON_OUTPUT" = true ]; then
        output_json
    else
        output_summary
    fi
}

# Run main function
main "$@"
