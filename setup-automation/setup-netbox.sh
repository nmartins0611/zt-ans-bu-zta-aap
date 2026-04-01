#!/bin/bash
set -euo pipefail

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
    while [[ "$1" != "--" ]]; do
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
# 1. Validate required variables
###############################################################################

for var in TMM_ORG TMM_ID; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set. Please export it before running."
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
# 3. Subscription Management (Direct Registration)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: System already registered."
else
    echo "Cleaning existing subscription data..."
    subscription-manager clean

    echo "Registering system with Org ID: ${TMM_ORG}..."
    subscription-manager register --org="$TMM_ORG" --activationkey="$TMM_ID" --force
    
    echo "Enabling repo management..."
    subscription-manager config --rhsm.manage_repos=1
    subscription-manager refresh
fi

###############################################################################
# 4. Install packages and Docker
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils git nano \
    -- \
    dnf install -y dnf-utils git nano

DOCKER_REPO_FILE="/etc/yum.repos.d/docker-ce.repo"

run_if_needed "Add Docker repo" \
    test -f "${DOCKER_REPO_FILE}" \
    -- \
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Note: On RHEL, Docker sometimes requires the 'container-tools' module to be disabled 
# if there are conflicts with podman/buildah, but usually dnf handles this now.
run_if_needed "Install Docker" \
    rpm -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    -- \
    dnf install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

###############################################################################
# 5. Enable & start Docker (idempotent)
###############################################################################

if ! systemctl is-enabled --quiet docker 2>/dev/null; then
    systemctl enable docker
else
    echo "SKIP: Docker already enabled"
fi

if ! systemctl is-active --quiet docker; then
    systemctl start docker
else
    echo "SKIP: Docker already running"
fi

###############################################################################
# 6. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 7. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.15/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up eth1 || true

###############################################################################
# 8. Clone NetBox Docker repo (idempotent)
###############################################################################

if [ -d /tmp/netbox-docker ]; then
    echo "SKIP: /tmp/netbox-docker already exists"
else
    retry "Clone netbox-docker repo" \
        git clone --depth=1 -b 3.3.0 \
        https://github.com/netbox-community/netbox-docker.git /tmp/netbox-docker
fi

###############################################################################
# 9. Docker Compose override
###############################################################################

# Writing the override file
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
# 10. Wait for Docker daemon and deploy NetBox
###############################################################################

for i in {1..10}; do
    if
