/**
 * Dashboard - Main Analytics Page
 */

import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AlertMetrics, TopAlerts } from '@/types'
import {
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Clock,
  CheckCircle,
  Activity,
} from 'lucide-react'

const MetricCard: React.FC<{
  title: string
  value: string | number
  change?: number
  icon: React.ReactNode
  color: 'primary' | 'success' | 'warning' | 'danger'
}> = ({ title, value, change, icon, color }) => {
  const colorClasses = {
    primary: 'bg-primary-500',
    success: 'bg-success-500',
    warning: 'bg-warning-500',
    danger: 'bg-danger-500',
  }

  return (
    <div className="card">
      <div className="card-body">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{title}</p>
            <p className="text-2xl font-bold text-gray-900 mt-2">{value}</p>
            {change !== undefined && (
              <div className="flex items-center mt-2">
                {change > 0 ? (
                  <TrendingUp className="w-4 h-4 text-success-600 mr-1" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-danger-600 mr-1" />
                )}
                <span className={`text-sm font-medium ${change > 0 ? 'text-success-600' : 'text-danger-600'}`}>
                  {Math.abs(change)}%
                </span>
                <span className="text-sm text-gray-500 ml-1">vs last period</span>
              </div>
            )}
          </div>
          <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
            {icon}
          </div>
        </div>
      </div>
    </div>
  )
}

export const Dashboard: React.FC = () => {
  // Fetch metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['metrics'],
    queryFn: () => api.analytics.getMetrics(),
  })

  // Fetch top alerts
  const { data: topAlerts, isLoading: topAlertsLoading } = useQuery({
    queryKey: ['top-alerts'],
    queryFn: () => api.analytics.getTopAlerts(5),
  })

  if (metricsLoading || topAlertsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    )
  }

  const totalAlerts = metrics?.total_alerts || 0
  const criticalAlerts = metrics?.by_severity?.critical || 0
  const avgResolutionTime = metrics?.avg_resolution_time || 0
  const mttr = metrics?.mttr || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-600 mt-1">Overview of security alerts and system performance</p>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Alerts"
          value={totalAlerts.toLocaleString()}
          change={12}
          icon={<AlertTriangle className="w-6 h-6 text-white" />}
          color="primary"
        />
        <MetricCard
          title="Critical Alerts"
          value={criticalAlerts.toLocaleString()}
          icon={<Activity className="w-6 h-6 text-white" />}
          color="danger"
        />
        <MetricCard
          title="Avg Resolution Time"
          value={`${Math.round(avgResolutionTime)}m`}
          change={-8}
          icon={<Clock className="w-6 h-6 text-white" />}
          color="warning"
        />
        <MetricCard
          title="MTTR"
          value={`${Math.round(mttr)}m`}
          change={-15}
          icon={<CheckCircle className="w-6 h-6 text-white" />}
          color="success"
        />
      </div>

      {/* Charts and Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by Severity */}
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Alerts by Severity</h2>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              {metrics?.by_severity && Object.entries(metrics.by_severity).map(([severity, count]) => (
                <div key={severity} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-3 h-3 rounded-full ${
                        severity === 'critical'
                          ? 'bg-danger-500'
                          : severity === 'high'
                          ? 'bg-warning-500'
                          : severity === 'medium'
                          ? 'bg-primary-500'
                          : 'bg-success-500'
                      }`}
                    />
                    <span className="text-sm font-medium text-gray-900 capitalize">{severity}</span>
                  </div>
                  <span className="text-sm text-gray-600">{count as number}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Alert Types */}
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Top Alert Types</h2>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              {topAlerts?.map((alert) => (
                <div key={alert.alert_type} className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-900 capitalize">
                    {alert.alert_type.replace('_', ' ')}
                  </span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-primary-600 h-2 rounded-full"
                        style={{ width: `${alert.percentage}%` }}
                      />
                    </div>
                    <span className="text-sm text-gray-600 w-12 text-right">{alert.count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">System Status</h2>
        </div>
        <div className="card-body">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <div className="w-2 h-2 bg-success-500 rounded-full animate-pulse" />
            All systems operational
          </div>
        </div>
      </div>
    </div>
  )
}
