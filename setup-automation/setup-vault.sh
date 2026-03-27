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
# 2. Network configuration (idempotent)
###############################################################################

ensure_nmcli_connection "eth1" \
    type ethernet con-name eth1 ifname eth1 \
    ipv4.addresses 192.168.1.12/24 \
    ipv4.method manual \
    connection.autoconnect yes

nmcli connection up eth1 || true
nmcli con mod eth1 ipv4.dns 192.168.1.11
nmcli con mod eth1 ipv4.dns-search zta.lab
nmcli connection up eth1 || true

###############################################################################
# 3. Apply Vault license and restart
###############################################################################

if [ -z "${VAULT_LIC:-}" ]; then
    echo "ERROR: VAULT_LIC environment variable is not set"
    exit 1
fi

VAULT_LIC_FILE="/etc/vault.d/vault.hclic"

echo "$VAULT_LIC" | sudo tee "$VAULT_LIC_FILE" > /dev/null
sudo chmod 640 "$VAULT_LIC_FILE"
sudo chown vault:vault "$VAULT_LIC_FILE"
echo "License file written to ${VAULT_LIC_FILE}"

sudo systemctl restart vault
sleep 3

if sudo systemctl is-active --quiet vault; then
    echo "✓ Vault restarted successfully"
else
    echo "ERROR: Vault service may not be running properly"
    sudo systemctl status vault
    exit 1
fi

###############################################################################
# 4. Unseal Vault (idempotent — unseal is a no-op if already unsealed)
###############################################################################

vault operator unseal \
    -address=http://127.0.0.1:8200 \
    -tls-skip-verify \
    1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5 \
    || echo "WARN: Vault unseal returned non-zero (may already be unsealed)"

echo "✓ vault setup complete"
