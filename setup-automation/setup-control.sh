#!/bin/bash
set -euo pipefail

echo "Starting Control node setup..."

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
    ipv4.addresses 192.168.1.10/24 \
    ipv4.method manual \
    ipv4.dns 192.168.1.11 \
    ipv4.dns-search zta.lab \
    connection.autoconnect yes

nmcli connection up eth1 || true

###############################################################################
# 5. Register with subscription manager (idempotent)
###############################################################################

if subscription-manager identity &>/dev/null; then
    echo "SKIP: Already registered – skipping registration"
else
    echo "Cleaning existing repos and subscriptions..."
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
# 6. Enable subscription-manager repo management (idempotent)
###############################################################################

CURRENT_MANAGE_REPOS=$(subscription-manager config --list | grep -oP 'manage_repos\s*=\s*\[\K[^\]]+' || echo "unknown")
if [ "$CURRENT_MANAGE_REPOS" = "1" ]; then
    echo "SKIP: manage_repos already enabled"
else
    subscription-manager config --rhsm.manage_repos=1
    subscription-manager refresh
fi

###############################################################################
# 7. Install packages
###############################################################################

run_if_needed "Install base packages" \
    rpm -q dnf-utils \
    -- \
    dnf install -y dnf-utils git nano

run_if_needed "Install IPA client packages" \
    rpm -q ipa-client \
    -- \
    dnf install -y ipa-client sssd oddjob-mkhomedir

run_if_needed "Install Python3 libraries" \
    rpm -q python3-libsemanage \
    -- \
    dnf install -y python3-libsemanage

###############################################################################
# 8. Clone workshop repo (optional, idempotent)
###############################################################################

# Uncomment if workshop repo is needed
# if [ -d /tmp/zta-aap-workshop ]; then
#     echo "SKIP: /tmp/zta-aap-workshop already exists"
# else
#     retry "Clone ZTA AAP workshop repo" \
#         git clone https://github.com/nmartins0611/zta-aap-workshop.git /tmp/zta-aap-workshop
# fi

echo ""
echo "✓ control setup complete"
