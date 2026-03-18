#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

retry() {
    local cmd="$1"
    local desc="${2:-$1}"
    for i in {1..3}; do
        echo "Attempt $i: $desc"
        if eval "$cmd"; then
            return 0
        fi
        [ $i -lt 3 ] && sleep 5
    done
    echo "ERROR: Failed after 3 attempts: $desc"
    exit 1
}

run_if_needed() {
    local check="$1"
    local cmd="$2"
    local desc="$3"
    if eval "$check" &>/dev/null; then
        echo "SKIP (already done): $desc"
    else
        retry "$cmd" "$desc"
    fi
}

# ─────────────────────────────────────────────
# 1. Validate required variables
# ─────────────────────────────────────────────

for var in SATELLITE_URL SATELLITE_ORG SATELLITE_ACTIVATIONKEY; do
    if [ -z "${!var}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

# ─────────────────────────────────────────────
# 2. Clean repos & subscriptions
#    Only wipe if NOT already registered — avoids
#    destroying a valid subscription on re-run
# ─────────────────────────────────────────────

if subscription-manager status &>/dev/null; then
    echo "SKIP: Already registered with Satellite – skipping clean/unregister"
else
    echo "Cleaning existing repos and subscriptions..."
    rm -rf /etc/yum.repos.d/*
    yum clean all
    subscription-manager unregister 2>/dev/null || true
    subscription-manager remove --all 2>/dev/null || true
    subscription-manager clean

    # Remove old Katello consumer RPM only when re-registering
    OLD_KATELLO=$(rpm -qa | grep katello-ca-consumer || true)
    [ -n "$OLD_KATELLO" ] && rpm -e "$OLD_KATELLO" 2>/dev/null || true
fi

# ─────────────────────────────────────────────
# 3. Register with Satellite
# ─────────────────────────────────────────────

CA_CERT="/etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"

run_if_needed \
    "test -f ${CA_CERT}" \
    "curl -fsSk -L https://${SATELLITE_URL}/pub/katello-server-ca.crt -o ${CA_CERT}" \
    "Download Katello CA cert"

retry "update-ca-trust" "Update CA trust"

run_if_needed \
    "rpm -q katello-ca-consumer" \
    "rpm -Uhv --force https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm" \
    "Install Katello consumer RPM"

run_if_needed \
    "subscription-manager status" \
    "subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}" \
    "Register with Satellite"

retry "subscription-manager refresh" "Refresh subscription"

# ─────────────────────────────────────────────
# 4. Install packages
# ─────────────────────────────────────────────

BASE_PKGS="dnf-utils git nano"

run_if_needed \
    "rpm -q ${BASE_PKGS}" \
    "dnf install -y ${BASE_PKGS}" \
    "Install base packages"

DOCKER_REPO_FILE="/etc/yum.repos.d/docker-ce.repo"

run_if_needed \
    "test -f ${DOCKER_REPO_FILE}" \
    "dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo" \
    "Add Docker repo"

SYSTEM_PKGS="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
             python3-pip python3-libsemanage git ansible-core python-requests
             ipa-client sssd oddjob-mkhomedir postgresql-server postgresql python3-psycopg2"

run_if_needed \
    "rpm -q ${SYSTEM_PKGS}" \
    "dnf install -y ${SYSTEM_PKGS}" \
    "Install Docker and system packages"

# ─────────────────────────────────────────────
# 5. Enable & start Docker
# ─────────────────────────────────────────────

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

echo "✓ Setup complete"
setenforce 0

echo "192.168.1.10 control.zta.lab control" >> /etc/hosts
echo "192.168.1.11 central.zta.lab  keycloak.zta.lab  opa.zta.lab" >> /etc/hosts
echo "192.168.1.12 vault.zta.lab vault" >> /etc/hosts
echo "192.168.1.13 wazuh.zta.lab wazuh" >> /etc/hosts
echo "192.168.1.14 node01.zta.lab node01" >> /etc/hosts
echo "192.168.1.15 netbox.zta.lab netbox" >> /etc/hosts

nmcli connection add type ethernet con-name eth1 ifname eth1 ipv4.addresses 192.168.1.14/24 ipv4.method manual connection.autoconnect yes
nmcli connection up eth1
nmcli con mod eth1 ipv4.dns 192.168.1.11
nmcli con mod eth1 ipv4.dns-search zta.lab
nmcli con up eth1



