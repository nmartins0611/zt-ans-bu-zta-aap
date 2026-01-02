#!/bin/bash

if [ -n "$VAULT_LIC" ]; then
    echo "$VAULT_LIC" > /etc/vault.d/vault.hclic
    echo "File created successfully"
    sudo systemctl restart vault
else
    echo "Error: VAULT_LIC environment variable is not set"
    exit 1
fi

vault operator unseal -address=http://127.0.0.1:8200 -tls-skip-verify 1c6a637e70172e3c249f77b653fb64a820749864cad7f5aa7ab6d5aca5197ec5
#
