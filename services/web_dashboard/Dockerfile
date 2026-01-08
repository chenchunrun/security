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

# =============================================================================
# Stage 1: Build React Frontend
# =============================================================================
FROM node:20-alpine AS frontend-builder

# Build context is ./services/web_dashboard
WORKDIR /frontend

# Copy frontend package files from current directory
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci

# Copy frontend source (current directory)
COPY . ./

# Build frontend
RUN npm run build

# =============================================================================
# Stage 2: Build Backend and Serve Frontend
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (from current directory)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared module (parent directory relative to build context)
COPY ../shared /app/shared

# Copy backend code (current directory)
COPY . /app/services/web_dashboard

# Copy built frontend from stage 1
COPY --from=frontend-builder /frontend/dist /app/static

# Create non-root user
RUN useradd -m -u 1000 triage && \
    chown -R triage:triage /app
USER triage

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Start FastAPI backend
CMD ["python", "main.py"]
