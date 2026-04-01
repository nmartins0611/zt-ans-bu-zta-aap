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

ensure_hosts_entry() {
    local ip="$1"
    local names="$2"
    if grep -q "^${ip} " /etc/hosts 2>/dev/null; then
        echo "SKIP: /etc/hosts already has entry for ${ip}"
    else
        echo "${ip} ${names}" >> /etc/hosts
    fi
}

ensure_nmcli_connection() {
    local con_name="$1"
    shift
    if nmcli connection show "$con_name" &>/dev/null; then
        echo "SKIP: nmcli connection '${con_name}' already exists"
    else
        nmcli connection add "$@"
    fi
}

###############################################################################
# 1. Validate required environment variables
###############################################################################

for var in TMM_ORG TMM_ID; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        echo "Usage: TMM_ORG='...' TMM_ID='...' $0"
        exit 1
    fi
done

###############################################################################
# 2. SELinux — set permissive (idempotent)
###############################################################################

CURRENT_MODE=$(getenforce)
if [ "${CURRENT_MODE}" = "Permissive" ] || [ "${CURRENT_MODE}" = "Disabled" ]; then
    echo "SKIP: SELinux already in ${CURRENT_MODE} mode"
else
    setenforce 0
    echo "SELinux set to Permissive"
fi

###############################################################################
# 3. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 4. Network configuration (idempotent)
###############################################################################

echo "Configuring network interface..."
ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.15/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up eth1 || true

###############################################################################
# 5. Register with subscription manager (idempotent)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered – skipping registration"
else
    echo "Cleaning existing subscription data..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    echo "Registering with subscription manager..."
    if subscription-manager register --org="$TMM_ORG" --activationkey="$TMM_ID" --force; then
        echo "System registered successfully!"
    else
        echo "Registration failed. Please check your credentials and network connection."
        exit 1
    fi
fi

###############################################################################
# 6. Install packages and Docker
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
# 7. Enable & start Docker (idempotent)
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
# 8. Wait for Docker daemon to be ready
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
# 9. Clone NetBox Docker repo (idempotent)
###############################################################################

if [ -d /tmp/netbox-docker ]; then
    echo "SKIP: /tmp/netbox-docker already exists"
else
    retry "Clone netbox-docker repo" \
        git clone --depth=1 -b 3.3.0 \
        https://github.com/netbox-community/netbox-docker.git /tmp/netbox-docker
fi

###############################################################################
# 10. Docker Compose override configuration
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
      start_period: 180s
EOF

###############################################################################
# 11. Deploy NetBox containers
###############################################################################

cd /tmp/netbox-docker

# Check if containers are already running
if docker compose ps | grep -q "netbox.*Up"; then
    echo "SKIP: NetBox containers already running"
else
    retry "Pull NetBox images" \
        docker compose pull

    retry "Start NetBox containers" \
        docker compose up -d netbox netbox-worker
fi

###############################################################################
# 12. Wait for NetBox to be ready
###############################################################################

echo "Waiting for NetBox to be ready..."
for i in {1..30}; do
    if curl -f -s http://localhost:8000 &>/dev/null; then
        echo "✓ NetBox is up and responding"
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
echo "✓ netbox setup complete"
