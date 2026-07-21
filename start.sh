#!/usr/bin/env bash
set -e

# Dynamically resolve project root directory
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configure environment
export CHUTNEY_DATA_DIR="/tmp/dittor_chutney"
export CHUTNEY_TOR="$REPO_ROOT/tor/src/app/tor"
export CHUTNEY_TOR_GENCERT="$REPO_ROOT/tor/src/tools/tor-gencert"
export DITTOR_PROOF_PATH="/tmp/dittor_chutney/nodes/000a/dittor_proof.txt"

echo "=== 1. Cleaning up background Tor processes ==="
pkill -9 tor 2>/dev/null || true
rm -rf /tmp/dittor_chutney

echo "=== 2. Configuring & Starting Chutney Network ==="
cd "$REPO_ROOT/chutney"
./chutney configure networks/basic-min
./chutney start networks/basic-min

echo "=== 3. Starting Java DKG + Tor Bridge ==="
cd "$REPO_ROOT/demo"
mvn exec:java -Dexec.mainClass="dittor.Main" -Djava.net.preferIPv4Stack=true
