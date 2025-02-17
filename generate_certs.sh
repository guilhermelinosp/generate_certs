#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

CA_KEY=""
CA_CERT=""
CA_CN=""
PASSWORD_CA=""

check_prerequisites() {
    if ! command -v openssl &>/dev/null; then
        echo "[ERROR] OpenSSL is not installed. Please install it and try again." >&2
        exit 1
    fi

    if [ ! -w "$(pwd)" ]; then
        echo "[ERROR] Current directory is not writable. Check permissions and try again." >&2
        exit 1
    fi
}

check_error() {
    local status=$?
    local cmd="${BASH_COMMAND:-unknown}"
    local custom_message="${1:-An error occurred.}"
    local exit_code="${2:-1}"

    if [ $status -ne 0 ]; then
        echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $custom_message" >&2
        echo "[DETAIL] Command '$cmd' failed with status $status." >&2
        exit "$exit_code"
    fi
}

generate_password() {
    PASSWORD=$(openssl rand -base64 32)
    echo "[INFO] Password generated automatically for the entity: $PASSWORD"
}

create_ca() {
    while true; do
        read -r -p "Enter the name for the Certificate Authority (CA): " CA_NAME
        CA_NAME="${CA_NAME:-localhost}"

        if [[ -n "$CA_NAME" ]]; then
            break
        else
            echo "[WARNING] CA name cannot be empty. Please enter a valid name."
        fi
    done

    CA_KEY="ca.$CA_NAME.key"
    CA_CERT="ca.$CA_NAME.crt"
    CA_CN="$CA_NAME"

    echo "[INFO] Using CA CN: $CA_CN"
    echo "[INFO] Using CA key file: $CA_KEY"
    echo "[INFO] Using CA certificate file: $CA_CERT"

    if [[ -f "$CA_KEY" || -f "$CA_CERT" ]]; then
        echo "[WARNING] CA key or certificate already exists. These will be overwritten."
        read -r -p "Do you want to continue? (y/n): " overwrite_choice
        if [[ ! "$overwrite_choice" =~ ^[Yy]$ ]]; then
            echo "[INFO] Aborting CA creation."
            return
        fi
    fi

    echo "[INFO] Generating CA key..."
    PASSWORD_CA=$(openssl rand -base64 32)
    echo "[INFO] CA Password generated automatically: $PASSWORD_CA"

    if openssl genpkey -algorithm RSA -out "$CA_KEY" -aes256 -pkeyopt rsa_keygen_bits:2048 -pass pass:"$PASSWORD_CA" < /dev/null > /dev/null 2>&1; then
        chmod 600 "$CA_KEY"
        echo "[INFO] CA key generated successfully."
    else
        echo "[ERROR] Failed to generate CA key."
        return 1
    fi

    echo "[INFO] Generating CA certificate..."
    if openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" -subj "/CN=$CA_CN" -passin pass:"$PASSWORD_CA" < /dev/null > /dev/null 2>&1; then
        chmod 644 "$CA_CERT"
        echo "[INFO] CA certificate generated successfully."
    else
        echo "[ERROR] Failed to generate CA certificate."
        return 1
    fi

    echo "[INFO] CA key and certificate created successfully!"
}

create_san_config() {
    local entity_dir=$1
    local entity_cn=$2

    SAN_CONFIG="$entity_dir/SAN_config.cnf"
    cat > "$SAN_CONFIG" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = US
ST = Default State
L = Default City
O = Default Company Ltd
OU = Default Organizational Unit
CN = $entity_cn
emailAddress = default@example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $entity_cn
DNS.2 = localhost
EOF
}

create_certificate() {
    local entity_dir=$1
    local entity_key=$2
    local entity_csr=$3
    local entity_cert=$4
    local entity_pfx=$5
    local entity_cn=$6
    local entity_password=$7

    mkdir -p "$entity_dir"
    echo "[INFO] Generating key for $entity_dir..."
    openssl genrsa -out "$entity_key" 2048
    check_error "Failed to generate key for $entity_dir."
    chmod 600 "$entity_key"

    create_san_config "$entity_dir" "$entity_cn"

    echo "[INFO] Generating CSR for $entity_dir..."
    openssl req -new -key "$entity_key" -out "$entity_csr" -subj "/CN=$entity_cn" -reqexts v3_req -config "$SAN_CONFIG"
    check_error "Failed to generate CSR for $entity_dir."

    echo "[INFO] Signing certificate for $entity_dir..."
    openssl x509 -req -in "$entity_csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$entity_cert" -days 365 -sha256 -extensions v3_req -extfile "$SAN_CONFIG" -passin pass:"$PASSWORD_CA"
    check_error "Failed to sign certificate for $entity_dir."

    echo "[INFO] Exporting $entity_dir certificate to PKCS#12..."
    openssl pkcs12 -export -out "$entity_pfx" -inkey "$entity_key" -in "$entity_cert" -password pass:"$entity_password"
    check_error "Failed to export $entity_dir certificate to PKCS#12."
    chmod 600 "$entity_pfx"

    rm -f "$SAN_CONFIG" "$entity_csr"
    echo "[INFO] Temporary files for $entity_cn removed successfully."
}

main() {
    check_prerequisites

    echo "[INFO] Starting certificate creation process..."
    create_ca

    while true; do
        read -r -p "Do you want to add a certificate to the CA? (y/n): " ADD_CERT
        if [[ "$ADD_CERT" != "y" ]]; then
            break
        fi

        read -r -p "Enter the Common Name (CN) for the certificate: " ENTITY_CN

        ENTITY_DIR="certificates/$ENTITY_CN"
        ENTITY_KEY="$ENTITY_DIR/$ENTITY_CN.key"
        ENTITY_CSR="$ENTITY_DIR/$ENTITY_CN.csr"
        ENTITY_CERT="$ENTITY_DIR/$ENTITY_CN.crt"
        ENTITY_PFX="$ENTITY_DIR/$ENTITY_CN.pfx"

        generate_password
        create_certificate "$ENTITY_DIR" "$ENTITY_KEY" "$ENTITY_CSR" "$ENTITY_CERT" "$ENTITY_PFX" "$ENTITY_CN" "$PASSWORD"

        echo "[INFO] Certificate for $ENTITY_CN created successfully!"
    done

    rm -f "ca.$CA_CN.srl"
    echo "[INFO] Certificate creation process completed!"
}

main "$@"
