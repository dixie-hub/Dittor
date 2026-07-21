# Dittor

Sybil-resilient Anonymous Credential Issuance Scheme for Tor

- Allows arbitrary threshold number and Certificate Authorities pool size, as long as t < n
- Uses Pederson Distributed Key Generation to generate the keys for each CA
- Partial blinded signatures are used for a Zero-Knowledge process 

Protocol:

1st Step:
    - User attends an event trusted by The Tor Project, and manifests his interest in running a Tor Node
    - Entity responsible for the event gives a random single-use code or a QR code to the user and registers this connection (avoiding sybils), with a secure protocol
2nd Step:
    - User logs into that Entity website (or another platform) on Tor with the single-use code
    - Single-use code is used as secret identity x in the Pedersen Commitment, with a random blinding factor
3rd Step:
    - Entity runs code and sends the user's request to the CA's, which can be Servers run by trusted worldwide Tor entities
    - User aggregates shares locally and computes the DY-VRF and the Schnorr Proof-of-Knowledge, and sends them to the DAs
4th Step:
    - DAs validate the credential and allow the User to run a Tor node!

src/main/java/
└── app/
    ├── Main.java                        // Bootstraps Babel, reads config, starts protocols
    ├── protocols/
    │   ├── UserProtocol.java            // (extends GenericProtocol) Handles User logic
    │   ├── CAProtocol.java              // (extends GenericProtocol) Handles CA signing logic
    │   └── DAProtocol.java              // (extends GenericProtocol) Handles DA verification
    ├── messages/
    │   ├── ca/
    │   │   ├── CredentialRequestMessage.java   // User -> CA (Sends blinded commitment)
    │   │   └── CredentialReplyMessage.java     // CA -> User (Returns signature share)
    │   └── da/
    │       ├── RegisterRelayMessage.java       // User -> DA (Sends PK, VRF, ZKP) - We just built this!
    │       └── RegisterRelayReplyMessage.java  // DA -> User (Success/Fail boolean)
    └── utils/
        └── CryptimeleonSetup.java       // Centralized BilinearGroup initialization

To start running:

I reccomend you run this in your Linux home filesystem, or your WSL mount:
cd ~
git clone <your-repo-url>

cd "/mnt/c/Users/donun/OneDrive/Ambiente de Trabalho/uni/5 ano/Tese/SASSIEmulation/Dittor/chutney"

export CHUTNEY_TOR="/mnt/c/Users/donun/OneDrive/Ambiente de Trabalho/uni/5 ano/Tese/SASSIEmulation/Dittor/tor/src/app/tor"
export CHUTNEY_TOR_GENCERT="/mnt/c/Users/donun/OneDrive/Ambiente de Trabalho/uni/5 ano/Tese/SASSIEmulation/Dittor/tor/src/tools/tor-gencert"

1 - Make the tor directory (this will take a while)
2 - Open two terminals, one for the Dittor Java system, another for Chutney
Dittor:
    cd demo
    mvn exec:java -Dexec.mainClass="dittor.Main" -Djava.net.preferIPv4Stack=true
Chutney:
