# Dittor

Sybil-resilient Anonymous Credential Issuance Scheme for Tor

- Allows arbitrary threshold number and Certificate Authorities pool size, as long as t < n
- Uses a Pedersen Verifiable Secret Sharing DKG (Gennaro et al. hash-commit-reveal, with per-share verification and disqualification of misbehaving CAs) to generate the keys for each CA, run as a real distributed exchange between CA processes — not a trusted-dealer simulation
- Partial blind signatures issued by the CAs are combined with a threshold Lagrange reconstruction to produce the anonymous credential
- A Dodis-Yampolskiy VRF produces a per-context pseudonym, and a DLEQ (Chaum-Pedersen) proof links that pseudonym to the credential without revealing the user's identity
- A Directory Authority keeps a pseudonym registry: the same underlying identity may register more than one relay only if it proves shared family (via Tor's `family-cert` mechanism) — otherwise it is rejected as a Sybil attempt

Protocol:

1st Step:
    - User attends an event trusted by The Tor Project, and manifests his interest in running a Tor Node
    - Entity responsible for the event gives a random single-use code or a QR code to the user and registers this connection (avoiding sybils), with a secure protocol
2nd Step:
    - User logs into that Entity website (or another platform) on Tor with the single-use code
    - Single-use code is used as secret identity x in the Pedersen Commitment, with a random blinding factor
3rd Step:
    - Entity runs code and sends the user's request to the CA's, which can be Servers run by trusted worldwide Tor entities
    - User aggregates shares locally (threshold Lagrange reconstruction) and computes the DY-VRF pseudonym and the DLEQ credential-linkage proof, and sends them to the DAs
4th Step:
    - DAs validate the VRF, the DLEQ credential linkage, and pseudonym uniqueness (with the family exception), and allow the User to run a Tor node!

## Código

Cada CA corre no seu próprio processo (`CAMain.java`) e fala com as outras CAs por
rede para gerar as chaves de forma distribuída (DKG real, não simulado). Um processo
`Main.java` simula um ou mais Users (um por nó Chutney) e faz de ponte para o Tor.

```
demo/src/main/java/dittor/
├── Main.java                     // Simula os Users (um por nó Chutney via DITTOR_NODES),
│                                  // pede a mpk a uma CA, corre o registo e exporta a prova
│                                  // (dittor_proof.txt / bridge_payload.txt) para o Tor/bridge
├── CAMain.java                    // Processo de uma CA: lê ca-config/ca-N.properties e
│                                  // arranca o CAProtocol (DKG distribuído + credenciais)
├── crypto/
│   ├── CryptimeleonSetup.java     // Curva (BLS12-381) e geradores partilhados (g1, h1, g2) —
│   │                              // usado por Main.java e CAMain.java para nunca divergirem
│   ├── CA.java                    // Pedersen VSS com a correção de Gennaro et al.
│   │                              // (hash-commit-reveal, verificação de shares, desqualificação)
│   ├── User.java                  // Blind commitment, agregação threshold, VRF, DLEQ
│   ├── DA.java                    // Verificação de VRF/DLEQ + registo de pseudónimos/família
│   └── vrf/
│       ├── DodisYampolskiyVRF.java
│       ├── DLEQZKP.java           // Prova de igualdade de logaritmo discreto (credencial <-> pseudónimo)
│       ├── Proof.java
│       └── VRFResult.java
├── protocols/                     // Protocolos Babel (rede)
│   ├── CAProtocol.java             // DKG distribuído entre CAs + emissão de partial signatures
│   ├── DAProtocol.java             // Recebe RegisterRelayMsg, valida e regista
│   ├── UserProtocol.java           // Pede credenciais às CAs, regista-se na DA
│   └── MasterPubKeyFetcher.java    // Usado pelo Main.java para obter a mpk de uma CA já pronta
├── messages/                       // Mensagens Babel (ca/ e da/)
├── tor/DAServer.java                // Bridge TCP simples que o Tor real usa (porta 8081)
└── testing/                         // BridgeTestClient.java / PayloadCorruptor.java, usados
                                      // nos testes documentados em demo/test-results/RESULTS.md
```

Pre-Requisites:
    - Java 8+ (JDK) for the Babel network and Cryptimeleon/mclwrap;
    - Maven to build the Java project (mvn clean install);
    - Python 3.10+ for Chutney;
    - Tor build dependencies (see tor/INSTALL).

I recommend you run this in your Linux home filesystem, or your WSL mount:

    cd ~
    git clone https://github.com/dixie-hub/Dittor.git

## Como correr

    ./start.sh

Isto configura e arranca a rede Chutney, e depois imprime os comandos a correr
manualmente, um por terminal (o `Main.java` não pode arrancar antes das CAs
terminarem o DKG, por isso não está tudo automatizado num único comando):

    Terminal 1 (CA-1): mvn exec:java -Dexec.mainClass=dittor.CAMain -Dexec.args=ca-config/ca-1.properties ...
    Terminal 2 (CA-2): idem, com ca-config/ca-2.properties
    Terminal 3 (CA-3): idem, com ca-config/ca-3.properties
    Terminal 4 (só depois das 3 CAs terminarem o DKG): mvn exec:java -Dexec.mainClass=dittor.Main ...

O threshold (`t`) e o tamanho do pool (`n`) não estão hardcoded no `Main.java` — são
lidos de `demo/ca-config/ca-1.properties`, e têm de ser consistentes nos três
ficheiros `ca-config/ca-*.properties`.

Variáveis de ambiente relevantes (já exportadas pelo `start.sh`):
    - DITTOR_NODES: lista de nós Chutney a simular, separados por vírgula (ex. "000a,001a,002r")
    - DITTOR_DATA_DIR: diretório de dados do Chutney, onde o Main.java escreve o
      dittor_proof.txt e o bridge_payload.txt de cada nó
    - DITTOR_PROOF_PATH: caminho alternativo para o dittor_proof.txt, quando
      DITTOR_NODES não está definido (modo de nó único, legado)
    - DITTOR_CA1_CONFIG: caminho alternativo para o ca-1.properties usado pelo
      Main.java para ler o threshold/n (por omissão: ca-config/ca-1.properties)

If ./start.sh does not work, try this first, and then try again:

    chmod +x start.sh

If this still does not work and you are using a version of python like 3.13 or higher, try downloading this missing backports:

    pip install pyasynchat --break-system-packages
    pip install pyasyncore legacy-cgi --break-system-packages

## Testes

Os resultados dos testes de rejeição de provas, resistência a Sybils (reutilização
de pseudónimo com e sem família partilhada), backend offline, e desempenho estão
documentados em [demo/test-results/RESULTS.md](demo/test-results/RESULTS.md).
