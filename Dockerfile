# ==============================================================================
# Multi-stage Dockerfile for SecureDB
# Stage 1: Build React Frontend
# Stage 2: Python 3.12 Backend with PostgreSQL CLI tools & Static Asset Serving
# ==============================================================================

# Stage 1: Build React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: SecureDB Python Runtime
FROM python:3.12-slim

# Install system dependencies including PostgreSQL 16 client utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application backend source
COPY app/ ./app
COPY scripts/ ./scripts

# Copy compiled React frontend distribution
COPY --from=frontend-builder /build/dist ./frontend/dist

# Create secure directories
RUN mkdir -p /app/storage/backups /app/storage/temp /app/storage/demo

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
