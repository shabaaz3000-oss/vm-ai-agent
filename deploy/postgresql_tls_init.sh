#!/bin/sh
set -eu

TLS_DIR="${POSTGRES_TLS_DIR:-/tls}"

mkdir -p "${TLS_DIR}"

POSTGRES_GID="$(id -g postgres)"

required_files="
ca.crt
server.crt
server.key
pg_hba.conf
"

present_count=0

for file in ${required_files}; do
    if [ -e "${TLS_DIR}/${file}" ]; then
        present_count=$((present_count + 1))
    fi
done

if [ "${present_count}" -ne 0 ] \
    && [ "${present_count}" -ne 4 ]; then
    echo "PostgreSQL TLS volume is incomplete." >&2
    exit 20
fi

if [ -e "${TLS_DIR}/ca.key" ]; then
    echo "PostgreSQL TLS volume contains forbidden CA private key." >&2
    exit 21
fi

if [ "${present_count}" -eq 4 ]; then
    openssl verify \
        -CAfile "${TLS_DIR}/ca.crt" \
        "${TLS_DIR}/server.crt" \
        >/dev/null

    openssl x509 \
        -in "${TLS_DIR}/server.crt" \
        -noout \
        -checkend 86400 \
        >/dev/null

    san_text="$(
        openssl x509 \
            -in "${TLS_DIR}/server.crt" \
            -noout \
            -ext subjectAltName
    )"

    printf '%s\n' "${san_text}" |
        grep -F "DNS:postgres" \
        >/dev/null

    chown root:root \
        "${TLS_DIR}/ca.crt" \
        "${TLS_DIR}/server.crt" \
        "${TLS_DIR}/pg_hba.conf"

    chown "0:${POSTGRES_GID}" \
        "${TLS_DIR}/server.key"

    chmod 0644 \
        "${TLS_DIR}/ca.crt" \
        "${TLS_DIR}/server.crt" \
        "${TLS_DIR}/pg_hba.conf"

    chmod 0640 \
        "${TLS_DIR}/server.key"

    echo "PostgreSQL TLS material already present and valid."
    exit 0
fi

umask 077

WORK_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "${WORK_DIR}"
}

trap cleanup EXIT HUP INT TERM

openssl genrsa \
    -out "${WORK_DIR}/ca.key" \
    2048 \
    >/dev/null 2>&1

openssl req \
    -x509 \
    -new \
    -key "${WORK_DIR}/ca.key" \
    -sha256 \
    -days 365 \
    -subj "/CN=AI Vulnerability Management Agent Local Compose CA" \
    -out "${WORK_DIR}/ca.crt" \
    >/dev/null 2>&1

openssl genrsa \
    -out "${WORK_DIR}/server.key" \
    2048 \
    >/dev/null 2>&1

openssl req \
    -new \
    -key "${WORK_DIR}/server.key" \
    -subj "/CN=postgres" \
    -out "${WORK_DIR}/server.csr" \
    >/dev/null 2>&1

cat > "${WORK_DIR}/server.ext" <<'EOF'
subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl x509 \
    -req \
    -in "${WORK_DIR}/server.csr" \
    -CA "${WORK_DIR}/ca.crt" \
    -CAkey "${WORK_DIR}/ca.key" \
    -CAcreateserial \
    -out "${WORK_DIR}/server.crt" \
    -days 365 \
    -sha256 \
    -extfile "${WORK_DIR}/server.ext" \
    >/dev/null 2>&1

cat > "${WORK_DIR}/pg_hba.conf" <<'EOF'
local all all trust
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::0/0 reject
hostssl all all 0.0.0.0/0 scram-sha-256
hostssl all all ::0/0 scram-sha-256
EOF

openssl verify \
    -CAfile "${WORK_DIR}/ca.crt" \
    "${WORK_DIR}/server.crt" \
    >/dev/null

san_text="$(
    openssl x509 \
        -in "${WORK_DIR}/server.crt" \
        -noout \
        -ext subjectAltName
)"

printf '%s\n' "${san_text}" |
    grep -F "DNS:postgres" \
    >/dev/null

mv "${WORK_DIR}/ca.crt" \
    "${TLS_DIR}/ca.crt"

mv "${WORK_DIR}/server.crt" \
    "${TLS_DIR}/server.crt"

mv "${WORK_DIR}/server.key" \
    "${TLS_DIR}/server.key"

mv "${WORK_DIR}/pg_hba.conf" \
    "${TLS_DIR}/pg_hba.conf"

chown root:root \
    "${TLS_DIR}/ca.crt" \
    "${TLS_DIR}/server.crt" \
    "${TLS_DIR}/pg_hba.conf"

chown "0:${POSTGRES_GID}" \
    "${TLS_DIR}/server.key"

chmod 0644 \
    "${TLS_DIR}/ca.crt" \
    "${TLS_DIR}/server.crt" \
    "${TLS_DIR}/pg_hba.conf"

chmod 0640 \
    "${TLS_DIR}/server.key"

test ! -e "${TLS_DIR}/ca.key"

echo "PostgreSQL TLS material initialized."
