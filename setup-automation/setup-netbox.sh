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

for var in SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set"
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
# 3. Clean repos & subscriptions (only if not registered)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered with Satellite – skipping clean/unregister"
else
    echo "Cleaning existing repos and subscriptions..."
    dnf clean all || true
    rm -f /etc/yum.repos.d/redhat-rhui*.repo
    sed -i 's/enabled=1/enabled=0/' /etc/dnf/plugins/amazon-id.conf 2>/dev/null || true
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    OLD_KATELLO=$(rpm -qa | grep katello-ca-consumer || true)
    if [ -n "$OLD_KATELLO" ]; then
        rpm -e "$OLD_KATELLO" 2>/dev/null || true
    fi
fi

###############################################################################
# 4. Register with Satellite
###############################################################################

CA_CERT="/etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"

run_if_needed "Download Katello CA cert" \
    test -f "${CA_CERT}" \
    -- \
    curl -fsSkL \
        "https://${SATELLITE_URL}/pub/katello-server-ca.crt" \
        -o "${CA_CERT}"

retry "Update CA trust" \
    update-ca-trust extract

run_if_needed "Install Katello consumer RPM" \
    rpm -q katello-ca-consumer \
    -- \
    rpm -Uhv --force "https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"

run_if_needed "Register with Satellite" \
    subscription-manager identity \
    -- \
    subscription-manager register \
        --org="${SATELLITE_ORG}" \
        --activationkey="${SATELLITE_ACTIVATIONKEY}"

retry "Refresh subscription" \
    subscription-manager refresh

###############################################################################
# 5. Install packages and Docker
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

run_if_needed "Install Docker" \
    rpm -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    -- \
    dnf install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

###############################################################################
# 6. Enable & start Docker (idempotent)
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
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab wazuh.zta.lab gitea.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"

###############################################################################
# 7. Network configuration (idempotent)
###############################################################################
###############################################################################
# 8. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.15/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up eth1 || true

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
# 10. Docker Compose override (always write — config may have changed)
###############################################################################

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
# 11. Wait for Docker daemon and deploy NetBox
###############################################################################

for i in {1..10}; do
    docker info &>/dev/null && break
    echo "Waiting for Docker daemon... ($i)"
    sleep 2
done

retry "Pull NetBox images" \
    docker compose --project-directory=/tmp/netbox-docker pull

retry "Start NetBox containers" \
    docker compose --project-directory=/tmp/netbox-docker up -d netbox netbox-worker

echo "✓ netbox setup complete"
