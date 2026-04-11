#!/bin/bash
set -euo pipefail

echo "Starting NetBox node setup..."

###############################################################################
# Helpers
###############################################################################

retry() {
    local max_attempts=3
    local delay=5
    local desc="$1"
    shift
    for ((i = 1; i <= max_attempts; i++)); do
        echo "Attempt $i/$max_attempts: $desc"
        if "$@"; then
            return 0
        fi
        if [ $i -lt $max_attempts ]; then
            echo "  Failed. Retrying in ${delay}s..."
            sleep $delay
        fi
    done
    echo "FATAL: Failed after $max_attempts attempts: $desc"
    exit 1
}

run_if_needed() {
    local desc="$1"
    shift
    local check=()
    while [[ $# -gt 0 && "${1}" != "--" ]]; do
        check+=("$1"); shift
    done
    shift
    if "${check[@]}" &>/dev/null; then
        echo "SKIP (already done): $desc"
    else
        retry "$desc" "$@"
    fi
}

###############################################################################
# 1. Install packages and Docker
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils \
    -- \
    dnf install -y dnf-utils git nano

DOCKER_REPO_FILE="/etc/yum.repos.d/docker-ce.repo"

run_if_needed "Add Docker repo" \
    test -f "${DOCKER_REPO_FILE}" \
    -- \
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

run_if_needed "Install Docker" \
    rpm -q docker-ce \
    -- \
    dnf install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

###############################################################################
# 2. Enable & start Docker (idempotent)
###############################################################################

if ! systemctl is-enabled --quiet docker 2>/dev/null; then
    systemctl enable docker
    echo "Docker enabled"
else
    echo "SKIP: Docker already enabled"
fi

if ! systemctl is-active --quiet docker; then
    systemctl start docker
    echo "Docker started"
else
    echo "SKIP: Docker already running"
fi

###############################################################################
# 3. Wait for Docker daemon to be ready
###############################################################################

echo "Waiting for Docker daemon to be ready..."
for i in {1..10}; do
    if docker info &>/dev/null; then
        echo "Docker daemon is ready"
        break
    fi
    echo "Waiting for Docker daemon... (attempt $i/10)"
    sleep 2
done

if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not responding after 20 seconds"
    exit 1
fi

###############################################################################
# 4. Clone NetBox Docker repo (idempotent)
###############################################################################

if [ -d /tmp/netbox-docker ]; then
    echo "SKIP: /tmp/netbox-docker already exists"
else
    retry "Clone netbox-docker repo" \
        git clone --depth=1 -b 3.3.0 \
        https://github.com/netbox-community/netbox-docker.git /tmp/netbox-docker
fi

###############################################################################
# 5. Docker Compose override configuration
###############################################################################

echo "Creating Docker Compose override configuration..."
cat > /tmp/netbox-docker/docker-compose.override.yml <<'EOF'
services:
  netbox:
    ports:
      - "8000:8080"
    environment:
      ALLOWED_HOSTS: "*"
      POSTGRES_USER: "netbox"
      POSTGRES_PASSWORD: "netbox"
      POSTGRES_DB: "netbox"
      POSTGRES_HOST: "postgres"
      REDIS_HOST: "redis"
      SKIP_SUPERUSER: "false"
      SUPERUSER_EMAIL: "admin@example.com"
      SUPERUSER_PASSWORD: "netbox"
      SUPERUSER_NAME: "admin"
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/login/ || exit 1"]
      start_period: 300s
      interval: 15s
      timeout: 5s
      retries: 3
EOF

###############################################################################
# 6. Deploy NetBox containers
###############################################################################

cd /tmp/netbox-docker

if docker compose ps | grep -q "netbox.*Up"; then
    echo "SKIP: NetBox containers already running"
else
    retry "Pull NetBox images" \
        docker compose pull

    docker compose up -d netbox

    echo "Waiting for NetBox container to become healthy..."
    health="starting"
    for i in {1..60}; do
        health=$(docker inspect --format='{{.State.Health.Status}}' netbox-docker-netbox-1 2>/dev/null || echo "missing")
        if [ "$health" = "healthy" ]; then
            echo "NetBox container is healthy"
            break
        fi
        echo "  Health status: $health (attempt $i/60)"
        sleep 5
    done

    if [ "$health" != "healthy" ]; then
        echo "ERROR: NetBox did not become healthy in time"
        docker compose logs netbox --tail=50
        exit 1
    fi

    docker compose up -d netbox-worker
fi

###############################################################################
# 7. Wait for NetBox to be ready
###############################################################################

echo "Waiting for NetBox to be ready..."
for i in {1..30}; do
    if curl -f -s http://localhost:8000 &>/dev/null; then
        echo "NetBox is up and responding"
        break
    fi
    echo "Waiting for NetBox to start... (attempt $i/30)"
    sleep 5
done

if curl -f -s http://localhost:8000 &>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  NetBox Setup Complete"
    echo "============================================================"
    echo "  URL: http://192.168.1.15:8000"
    echo "  Username: admin"
    echo "  Password: netbox"
    echo "============================================================"
else
    echo ""
    echo "WARNING: NetBox may not be fully ready yet"
    echo "Check status with: docker compose -f /tmp/netbox-docker/docker-compose.yml ps"
fi

echo ""
echo "netbox setup complete"
