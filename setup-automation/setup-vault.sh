#!/bin/bash
set -euo pipefail

echo "Starting Vault node setup..."

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

for var in TMM_ORG TMM_ID VAULT_LIC; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        echo "Usage: TMM_ORG='...' TMM_ID='...' VAULT_LIC='...' $0"
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
    ipv4.addresses 192.168.1.12/24 \
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
# 6. Apply Vault license (idempotent)
###############################################################################

VAULT_LIC_FILE="/etc/vault.d/vault.hclic"

# Check if license file already exists with same content
if [ -f "$VAULT_LIC_FILE" ]; then
    EXISTING_LIC=$(cat "$VAULT_LIC_FILE")
    if [ "$EXISTING_LIC" = "$VAULT_LIC" ]; then
        echo "SKIP: Vault license already configured with same content"
        LICENSE_UPDATED=false
    else
        echo "Updating Vault license file..."
        echo "$VAULT_LIC" | sudo tee "$VAULT_LIC_FILE" > /dev/null
        sudo chmod 640 "$VAULT_LIC_FILE"
        sudo chown vault:vault "$VAULT_LIC_FILE"
        echo "License file updated at ${VAULT_LIC_FILE}"
        LICENSE_UPDATED=true
    fi
else
    echo "Creating Vault license file..."
    echo "$VAULT_LIC" | sudo tee "$VAULT_LIC_FILE" > /dev/null
    sudo chmod 640 "$VAULT_LIC_FILE"
    sudo chown vault:vault "$VAULT_LIC_FILE"
    echo "License file written to ${VAULT_LIC_FILE}"
    LICENSE_UPDATED=true
fi

###############################################################################
# 8. Enable and start Vault service (idempotent)
###############################################################################

if ! systemctl is-enabled --quiet vault 2>/dev/null; then
    sudo systemctl enable vault
    echo "Vault service enabled"
else
    echo "SKIP: Vault service already enabled"
fi

# Restart vault only if license was updated
if [ "$LICENSE_UPDATED" = true ]; then
    echo "Restarting Vault service due to license update..."
    sudo systemctl restart vault
    sleep 3
else
    # Start if not running
    if ! systemctl is-active --quiet vault; then
        echo "Starting Vault service..."
        sudo systemctl start vault
        sleep 3
    else
        echo "SKIP: Vault service already running"
    fi
fi

# Verify vault is running
if sudo systemctl is-active --quiet vault; then
    echo "✓ Vault service is running"
else
    echo "ERROR: Vault service may not be running properly"
    sudo systemctl status vault
    exit 1
fi

###############################################################################
# 9. Unseal Vault (idempotent)
###############################################################################

echo "Checking Vault seal status..."

# Check if vault is already unsealed
SEAL_STATUS=$(vault status -address=http://127.0.0.1:8200 -format=json 2>/dev/null | grep -o '"sealed":[^,]*' | cut -d: -f2 || echo "true")

if [ "$SEAL_STATUS" = "false" ]; then
    echo "SKIP: Vault is already unsealed"
else
    echo "Unsealing Vault..."
    # NOTE: Unseal key is hardcoded for lab environment only
    # In production, use secure key management
    if vault operator unseal \
        -address=http://127.0.0.1:8200 \
        -tls-skip-verify \
        1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5; then
        echo "✓ Vault unsealed successfully"
    else
        echo "WARNING: Vault unseal returned non-zero (may already be unsealed or need additional keys)"
    fi
fi

# Verify final status
if vault status -address=http://127.0.0.1:8200 &>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  Vault Setup Complete"
    echo "============================================================"
    echo "  Vault URL: http://192.168.1.12:8200"
    echo "  Status: $(vault status -address=http://127.0.0.1:8200 -format=json 2>/dev/null | grep -o '"sealed":[^,]*' | cut -d: -f2 | sed 's/false/Unsealed/;s/true/Sealed/')"
    echo "============================================================"
else
    echo "WARNING: Could not verify Vault status"
fi

echo ""
echo "✓ vault setup complete"
