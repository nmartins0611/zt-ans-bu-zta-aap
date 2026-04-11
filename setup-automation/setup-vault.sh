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

for var in VAULT_LIC; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var environment variable is not set"
        exit 1
    fi
done

###############################################################################
# 2. Stop crash-looping Vault service (clean slate)
###############################################################################

if systemctl is-active --quiet vault 2>/dev/null || systemctl is-failed --quiet vault 2>/dev/null; then
    echo "Stopping Vault service before applying configuration fixes..."
    sudo systemctl stop vault
    sudo systemctl reset-failed vault 2>/dev/null || true
    echo "Vault service stopped"
else
    echo "SKIP: Vault service not running"
fi

###############################################################################
# 3. Patch storage backend: file -> raft (idempotent)
###############################################################################

VAULT_HCL="/etc/vault.d/vault.hcl"

if grep -q 'storage "file"' "$VAULT_HCL" 2>/dev/null; then
    echo "Patching vault.hcl: changing storage backend from 'file' to 'raft'..."
    sudo sed -i 's/storage "file"/storage "raft"/' "$VAULT_HCL"
    echo "Storage backend updated to 'raft'"
elif grep -q 'storage "raft"' "$VAULT_HCL" 2>/dev/null; then
    echo "SKIP: Storage backend already set to 'raft'"
else
    echo "WARNING: Could not detect storage backend in $VAULT_HCL"
fi

###############################################################################
# 4. Apply Vault license (idempotent)
###############################################################################

VAULT_LIC_FILE="/etc/vault.d/vault.hclic"

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
# 5. License diagnostics
###############################################################################

echo "Vault version: $(vault version 2>/dev/null || echo 'UNKNOWN')"
if [ -f "$VAULT_LIC_FILE" ] && [ -s "$VAULT_LIC_FILE" ]; then
    echo "License file: ${VAULT_LIC_FILE} ($(wc -c < "$VAULT_LIC_FILE") bytes)"
    echo "License prefix: $(head -c 20 "$VAULT_LIC_FILE")..."
else
    echo "WARNING: License file is missing or empty at ${VAULT_LIC_FILE}"
fi

###############################################################################
# 6. Enable and start Vault service
###############################################################################

if ! systemctl is-enabled --quiet vault 2>/dev/null; then
    sudo systemctl enable vault
    echo "Vault service enabled"
else
    echo "SKIP: Vault service already enabled"
fi

echo "Starting Vault service..."
sudo systemctl start vault
sleep 5

if sudo systemctl is-active --quiet vault; then
    echo "Vault service is running"
else
    echo "ERROR: Vault service failed to start"
    sudo journalctl -u vault --no-pager -n 20
    exit 1
fi

###############################################################################
# 7. Unseal Vault (idempotent)
###############################################################################

echo "Checking Vault seal status..."

SEAL_STATUS=$(vault status -address=http://127.0.0.1:8200 -format=json 2>/dev/null | grep -o '"sealed":[^,]*' | cut -d: -f2 || echo "true")

if [ "$SEAL_STATUS" = "false" ]; then
    echo "SKIP: Vault is already unsealed"
else
    echo "Unsealing Vault..."
    if vault operator unseal \
        -address=http://127.0.0.1:8200 \
        -tls-skip-verify \
        1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5; then
        echo "Vault unsealed successfully"
    else
        echo "WARNING: Vault unseal returned non-zero (may already be unsealed or need additional keys)"
    fi
fi

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
echo "vault setup complete"
