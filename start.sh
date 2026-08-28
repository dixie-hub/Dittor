#!/usr/bin/env bash
set -e

# Dynamically resolve project root directory
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configure environment
export CHUTNEY_DATA_DIR="/tmp/dittor_chutney"
export CHUTNEY_TOR="$REPO_ROOT/tor/src/app/tor"
export CHUTNEY_TOR_GENCERT="$REPO_ROOT/tor/src/tools/tor-gencert"
export DITTOR_DATA_DIR="/tmp/dittor_chutney"
export DITTOR_PROOF_PATH="/tmp/dittor_chutney/nodes/000a/dittor_proof.txt"
export DITTOR_NODES="000a,001a,002r"

echo "=== 1. Cleaning up background Tor and CA processes ==="
pkill -9 tor 2>/dev/null || true
pkill -9 -f dittor.CAMain 2>/dev/null || true
rm -rf /tmp/dittor_chutney

echo "=== 2. Configuring & Starting Chutney Network ==="
cd "$REPO_ROOT/chutney"
./chutney configure networks/basic-min
./chutney start networks/basic-min

echo ""
echo "=== Chutney está a correr. Falta lançar manualmente, cada um no seu terminal WSL: ==="
echo ""
echo "Terminal 1 (CA-1):"
echo "  cd '$REPO_ROOT/demo' && mvn exec:java -Dexec.mainClass=dittor.CAMain -Dexec.args=ca-config/ca-1.properties -Djava.net.preferIPv4Stack=true"
echo ""
echo "Terminal 2 (CA-2):"
echo "  cd '$REPO_ROOT/demo' && mvn exec:java -Dexec.mainClass=dittor.CAMain -Dexec.args=ca-config/ca-2.properties -Djava.net.preferIPv4Stack=true"
echo ""
echo "Terminal 3 (CA-3):"
echo "  cd '$REPO_ROOT/demo' && mvn exec:java -Dexec.mainClass=dittor.CAMain -Dexec.args=ca-config/ca-3.properties -Djava.net.preferIPv4Stack=true"
echo ""
echo "Terminal 4 (depois das 3 CAs completarem o DKG -- Main.java):"
echo "  export DITTOR_DATA_DIR='/tmp/dittor_chutney'"
echo "  export DITTOR_PROOF_PATH='/tmp/dittor_chutney/nodes/000a/dittor_proof.txt'"
echo "  export DITTOR_NODES='000a,001a,002r'"
echo "  cd '$REPO_ROOT/demo' && mvn exec:java -Dexec.mainClass=dittor.Main -Djava.net.preferIPv4Stack=true"