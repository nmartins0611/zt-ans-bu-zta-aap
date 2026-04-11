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

###############################################################################
# 1. Validate required environment variables
###############################################################################

if [ -z "${VAULT_LIC:-}" ]; then
    echo "ERROR: VAULT_LIC environment variable is not set"
    exit 1
fi

###############################################################################
# 2. Apply Vault license (idempotent)
#    The vault-rhel-image-1 VM ships pre-initialized with storage "file" and
#    a known unseal key. Only the license needs updating each deployment.
###############################################################################

VAULT_LIC_FILE="/etc/vault.d/vault.hclic"

if [ -f "$VAULT_LIC_FILE" ]; then
    EXISTING_LIC=$(cat "$VAULT_LIC_FILE")
    if [ "$EXISTING_LIC" = "$VAULT_LIC" ]; then
        echo "SKIP: Vault license already matches"
    else
        echo "Updating Vault license file..."
        echo "$VAULT_LIC" | sudo tee "$VAULT_LIC_FILE" > /dev/null
        sudo chmod 640 "$VAULT_LIC_FILE"
        sudo chown vault:vault "$VAULT_LIC_FILE"
        echo "License file updated at ${VAULT_LIC_FILE}"
    fi
else
    echo "Creating Vault license file..."
    echo "$VAULT_LIC" | sudo tee "$VAULT_LIC_FILE" > /dev/null
    sudo chmod 640 "$VAULT_LIC_FILE"
    sudo chown vault:vault "$VAULT_LIC_FILE"
    echo "License file written to ${VAULT_LIC_FILE}"
fi

###############################################################################
# 3. Diagnostics
###############################################################################

echo "Vault version: $(vault version 2>/dev/null || echo 'UNKNOWN')"
if [ -f "$VAULT_LIC_FILE" ] && [ -s "$VAULT_LIC_FILE" ]; then
    echo "License file: ${VAULT_LIC_FILE} ($(wc -c < "$VAULT_LIC_FILE") bytes)"
else
    echo "WARNING: License file is missing or empty at ${VAULT_LIC_FILE}"
fi

###############################################################################
# 4. Restart Vault service to pick up the license
###############################################################################

echo "Restarting Vault service..."
sudo systemctl restart vault
sleep 5

if sudo systemctl is-active --quiet vault; then
    echo "Vault service is running"
else
    echo "ERROR: Vault service failed to start"
    sudo journalctl -u vault --no-pager -n 30
    exit 1
fi

###############################################################################
# 5. Unseal Vault (idempotent)
#    The VM image is pre-initialized with this unseal key.
###############################################################################

UNSEAL_KEY="1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5"

SEAL_STATUS=$(vault status -address=http://127.0.0.1:8200 -format=json 2>/dev/null \
    | grep -o '"sealed":[^,]*' | cut -d: -f2 || echo "true")

if [ "$SEAL_STATUS" = "false" ]; then
    echo "SKIP: Vault is already unsealed"
else
    echo "Unsealing Vault..."
    retry "Unseal Vault" \
        vault operator unseal \
            -address=http://127.0.0.1:8200 \
            -tls-skip-verify \
            "$UNSEAL_KEY"
    echo "Vault unsealed successfully"
fi

###############################################################################
# 6. Final status
###############################################################################

if vault status -address=http://127.0.0.1:8200 &>/dev/null; then
    echo ""
    echo "============================================================"
    echo "  Vault Setup Complete"
    echo "============================================================"
    echo "  Vault URL: http://192.168.1.12:8200"
    SEALED=$(vault status -address=http://127.0.0.1:8200 -format=json 2>/dev/null \
        | grep -o '"sealed":[^,]*' | cut -d: -f2 \
        | sed 's/false/Unsealed/;s/true/Sealed/')
    echo "  Status: ${SEALED}"
    echo "============================================================"
else
    echo "WARNING: Could not verify Vault status"
fi

echo ""
echo "vault setup complete"
