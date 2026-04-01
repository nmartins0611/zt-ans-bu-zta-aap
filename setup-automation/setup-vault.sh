#!/bin/bash
set -euo pipefail

###############################################################################
# Helpers
###############################################################################

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
# 1. Validate Environment Variables
###############################################################################

for var in TMM_ORG TMM_ID VAULT_LIC; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set. Please export it before running."
        exit 1
    fi
done

###############################################################################
# 2. Subscription Management (Direct Registration)
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
# 3. Network configuration (idempotent)
###############################################################################

# Added DNS and Search Domain directly into the 'add' logic if it were to be created
ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.12/24 \
    ipv4.method manual \
    connection.autoconnect yes

# Ensure DNS settings are correct even if the connection already existed
echo "Configuring DNS for eth1..."
nmcli con mod eth1 ipv4.dns "192.168.1.11" ipv4.dns-search "zta.lab"
nmcli connection up eth1 || true

###############################################################################
# 4. /etc/hosts (idempotent)
###############################################################################

ensure_hosts_entry "192.168.1.10" "control.zta.lab control aap.zta.lab"
ensure_hosts_entry "192.168.1.11" "central.zta.lab central keycloak.zta.lab opa.zta.lab splunk.zta.lab db.zta.lab app.zta.lab ceos1.zta.lab ceos2.zta.lab ceos3.zta.lab"
ensure_hosts_entry "192.168.1.12" "vault.zta.lab vault"
ensure_hosts_entry "192.168.1.15" "netbox.zta.lab netbox"
ensure_hosts_entry "192.168.1.13" "wazuh.zta.lab wazuh"

###############################################################################
# 5. Apply Vault license and restart
###############################################################################

VAULT_LIC_FILE="/etc/vault.d/vault.hclic"

# Ensure directory exists before writing
mkdir -p /etc/vault.d/

echo "$VAULT_LIC" | tee "$VAULT_LIC_FILE" > /dev/null
chmod 640 "$VAULT_LIC_FILE"
chown vault:vault "$VAULT_LIC_FILE" 2>/dev/null || echo "WARN: Could not change ownership to vault user"

echo "License file written to ${VAULT_LIC_FILE}"

systemctl restart vault
sleep 3

if systemctl is-active --quiet vault; then
    echo "✓ Vault restarted successfully"
else
    echo "ERROR: Vault service is not running"
    systemctl status vault
    exit 1
fi

###############################################################################
# 6. Unseal Vault
###############################################################################

# Using a subshell to ignore errors if already unsealed
echo "Attempting to unseal Vault..."
vault operator unseal \
    -address=http://127.0.0.1:8200 \
    1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5 || echo "Vault unseal step finished (it may already be unsealed)."

echo "✓ vault setup complete"
