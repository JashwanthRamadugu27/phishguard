# ==============================================================================
# Multi-Stage Hardened Dockerfile for Phishing Sentinel AI Agent & Web Console
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Modern React Frontend (Vite + TailwindCSS)
# ------------------------------------------------------------------------------
FROM node:20-slim AS frontend-builder
WORKDIR /frontend

# Install dependencies
COPY frontend/package*.json ./
RUN npm install

# Build production assets to /frontend/dist
COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Python Dependency Builder
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS builder
WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 3: Final Hardened Runtime Container
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runner
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PYTHONPATH=/app

# Create non-root unprivileged system user and persistent storage directories
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Copy Python packages from builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copy backend application source code, tools, and sample dataset
COPY --chown=appuser:appuser ./app /app/app
COPY --chown=appuser:appuser ./view_memory.py /app/
COPY --chown=appuser:appuser ./sample_phish.eml /app/
COPY --chown=appuser:appuser ./requirements.txt /app/

# Copy compiled frontend dist so FastAPI can serve the Cyber Command Center UI
COPY --from=frontend-builder --chown=appuser:appuser /frontend/dist /app/frontend/dist

# Switch to non-root user for container security
USER appuser

# Expose Web Command Center & API port
EXPOSE 8000

# Health check to ensure API endpoint and memory store are responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

# Default Entrypoint: Launch FastAPI server (Serves Web UI on / and API on /api)
ENTRYPOINT ["python", "-m", "uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
