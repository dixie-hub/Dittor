package dittor;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

import dittor.crypto.CryptimeleonSetup;
import dittor.crypto.DA;
import dittor.crypto.User;
import dittor.crypto.vrf.DLEQZKP;
import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.VRFResult;
import dittor.protocols.DAProtocol;
import dittor.protocols.MasterPubKeyFetcher;
import dittor.protocols.UserProtocol;
import dittor.tor.DAServer;
import pt.unl.fct.di.novasys.babel.core.Babel;
import pt.unl.fct.di.novasys.network.data.Host;

public class Main {

    // Escreve para um ficheiro temporário no mesmo diretório e troca-o atomicamente
    // (rename) para o caminho final, para que o Tor nunca veja o ficheiro a meio
    // de uma escrita quando o reinjeta periodicamente em router.c.
    // Constrói as duas representações da prova a partir da MESMA lista de campos, na
    // mesma ordem, para nunca voltar a dessincronizar os índices entre o dittor_proof.txt
    // (consumido pelo Tor, delimitado por espaços) e o bridge_payload.txt (para testes
    // diretos à bridge, delimitado por pipes, com nodeId/familyIds adicionais).
    private static String buildDittorProofLine(String context, String pkJSON, String nymJSON, String zkpJSON,
            String g1xJSON, String credentialJSON, String dleqChallengeJSON, String dleqResponseJSON) {
        return String.join(" ", "dittor-proof", context, pkJSON, nymJSON, zkpJSON, g1xJSON, credentialJSON,
                dleqChallengeJSON, dleqResponseJSON);
    }

    private static String buildBridgePayloadLine(String context, String pkJSON, String nymJSON, String zkpJSON,
            String g1xJSON, String credentialJSON, String dleqChallengeJSON, String dleqResponseJSON,
            String nodeId, String familyIds) {
        return String.join("|", context, pkJSON, nymJSON, zkpJSON, g1xJSON, credentialJSON, dleqChallengeJSON,
                dleqResponseJSON, nodeId, familyIds);
    }

    // Mostra um resumo legível da prova Dittor gerada, com o valor de cada campo
    // truncado e identificado por label — o conteúdo completo continua a ir para o
    // ficheiro (writeFileAtomically), isto é só para quem está a acompanhar a demo
    // no terminal conseguir situar-se sem se perder num bloco gigante de números.
    private static String truncateForDisplay(String value, int maxLen) {
        if (value.length() <= maxLen) {
            return value;
        }
        return value.substring(0, maxLen) + "...";
    }

    private static void printProofSummary(String nodeName, String context, String pkJSON, String nymJSON,
            String zkpJSON, String g1xJSON, String credentialJSON, String dleqChallengeJSON,
            String dleqResponseJSON) {
        int maxLen = 40;
        System.out.println("\n=== Dittor proof generated for node " + nodeName + " ===");
        System.out.println("  Context:             " + context);
        System.out.println("  Public Key (pk):     " + truncateForDisplay(pkJSON, maxLen));
        System.out.println("  Pseudonym (nym):     " + truncateForDisplay(nymJSON, maxLen));
        System.out.println("  VRF Proof (pi):      " + truncateForDisplay(zkpJSON, maxLen));
        System.out.println("  Commitment (g1^x):   " + truncateForDisplay(g1xJSON, maxLen));
        System.out.println("  Credential (sigma):  " + truncateForDisplay(credentialJSON, maxLen));
        System.out.println("  DLEQ Challenge:      " + truncateForDisplay(dleqChallengeJSON, maxLen));
        System.out.println("  DLEQ Response:       " + truncateForDisplay(dleqResponseJSON, maxLen));
        System.out.println("===================================================\n");
    }

    private static void writeFileAtomically(String targetPath, String content) throws IOException {
        Path target = Paths.get(targetPath).toAbsolutePath();
        Path parent = target.getParent();
        Path tmp = Files.createTempFile(parent, target.getFileName().toString(), ".tmp");
        try {
            Files.write(tmp, content.getBytes(StandardCharsets.UTF_8));
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    public static void main(String[] args) throws Exception {

        // ---------------------------------------------------------
        // 1. CRYPTOGRAPHIC SETUP
        // ---------------------------------------------------------

        // threshold/n lidos do config da CA-1, para nunca dessincronizarem dos
        // valores que as CAs (CAMain.java) realmente estão a usar no DKG
        String caConfigPath = System.getenv().getOrDefault("DITTOR_CA1_CONFIG", "ca-config/ca-1.properties");
        Properties caConfig = new Properties();
        try (InputStream in = new FileInputStream(caConfigPath)) {
            caConfig.load(in);
        }
        int t = Integer.parseInt(caConfig.getProperty("threshold"));
        int n = Integer.parseInt(caConfig.getProperty("n"));

        System.out.println("Initializing Bilinear Group...");
        CryptimeleonSetup setup = new CryptimeleonSetup();
        BilinearGroup pairing = setup.getPairing();

        GroupElement g1 = setup.getG1();
        GroupElement h1 = setup.getH1();
        GroupElement g2 = setup.getG2();

        DodisYampolskiyVRF vrf = new DodisYampolskiyVRF(pairing);
        DLEQZKP dleqZKP = new DLEQZKP(pairing);

        // ---------------------------------------------------------
        // 2. BABEL NETWORK
        // ---------------------------------------------------------

        System.out.println("\n--- Initializing Babel Network Framework ---");
        Babel babel = Babel.getInstance();
        String localhost = InetAddress.getByName("127.0.0.1").getHostAddress();

        // Endereços das CAs, iguais com demo/ca-config/ca-*.properties
        Map<Host, Integer> caNetworkMap = new HashMap<>();
        int caBasePort = 10000;
        for (int i = 1; i <= n; i++) {
            caNetworkMap.put(new Host(InetAddress.getByName(localhost), caBasePort + i), i);
        }

        // pergunta a mpk a uma CA que já esteja pronta, e repete até o DKG estar
        // finalizado
        System.out.println("Fetching master public key from CA-1...");
        MasterPubKeyFetcher mpkFetcher = new MasterPubKeyFetcher(pairing);
        Properties fetcherProperties = new Properties();
        fetcherProperties.setProperty("address", localhost);
        fetcherProperties.setProperty("port", "9500");
        babel.registerProtocol(mpkFetcher);
        mpkFetcher.init(fetcherProperties);
        mpkFetcher.start();

        Host firstCAHost = new Host(InetAddress.getByName(localhost), caBasePort + 1);
        GroupElement[] mpk = mpkFetcher.fetchBlocking(firstCAHost, 1, 10, 3000);
        GroupElement mpkG1 = mpk[0];
        GroupElement mpkG2 = mpk[1];
        System.out.println("Master public key received!");

        // Setup DA on port 10000
        System.out.println("Starting DA node on port 10000");
        DA cryptoDA = new DA(vrf, dleqZKP, pairing, g1, g2, mpkG2);
        DAProtocol daProtocol = new DAProtocol(pairing, cryptoDA);
        Properties daProperties = new Properties();
        daProperties.setProperty("address", localhost);
        daProperties.setProperty("port", "10000");
        Host daHost = new Host(InetAddress.getByName(localhost), 10000);

        babel.registerProtocol(daProtocol);
        daProtocol.init(daProperties);
        daProtocol.start();

        System.out.println("Babel successfully running");

        // extra time to make sure server sockets bind to the OS ports
        Thread.sleep(1000);

        // ---------------------------------------------------------
        // 3. START TOR BRIDGE
        // ---------------------------------------------------------
        System.out.println("Starting Tor bridge on port 8081...");

        DAServer torBridge = new DAServer(8081, pairing, cryptoDA);
        Thread torBridgeThread = new Thread(torBridge);
        torBridgeThread.start();

        // ---------------------------------------------------------
        // 4. TRIGGER PROTOCOL EXECUTION (um relay simulado por nó Chutney)
        // ---------------------------------------------------------
        String nodesEnv = System.getenv("DITTOR_NODES");

        List<String> nodeNames = new ArrayList<>();
        if (nodesEnv == null || nodesEnv.trim().isEmpty())
            nodeNames.add("000a");
        else {
            for (String name : nodesEnv.split(",")) {
                nodeNames.add(name.trim());
            }
        }
        String dataDir = System.getenv("DITTOR_DATA_DIR");

        for (int i = 0; i < nodeNames.size(); i++) {
            String nodeName = nodeNames.get(i);
            System.out.println(
                    "\n--- Starting User node for Chutney node " + nodeName + " (port " + (8050 + i) + ") ---");

            User cryptoUser = new User(pairing);
            UserProtocol userProtocol = new UserProtocol(pairing, cryptoUser, t, vrf, dleqZKP, g1, h1, mpkG1,
                    mpkG2, g1, g2, nodeName, new ArrayList<>(), i);
            Properties userProperties = new Properties();
            userProperties.setProperty("address", localhost);
            userProperties.setProperty("port", String.valueOf(8050 + i));

            babel.registerProtocol(userProtocol);
            userProtocol.init(userProperties);
            userProtocol.start();

            Thread.sleep(500);

            System.out.println("Triggering User Protocol to begin network handshake for node " + nodeName + "...");
            userProtocol.startRegistration(caNetworkMap, daHost);

            Thread.sleep(2500); // to make sure the protocol async tasks are complete
            try {
                JSONConverter jsonConverter = new JSONConverter();

                String context = "TorRelayConsensus2026";

                GroupElement userPubKey = userProtocol.getUserPubKey();
                VRFResult vrfResult = userProtocol.getVrfResult();

                GroupElement g1x = userProtocol.getCredentialCommitmentG1();

                GroupElement credential = userProtocol.getCredential();
                Proof dleqProof = userProtocol.getDleqProof();
                String realPkJSON = jsonConverter.serialize(userPubKey.getRepresentation());
                String realNymJSON = jsonConverter.serialize(vrfResult.getPseudonym().getRepresentation());
                String realVrfZkpJSON = jsonConverter.serialize(vrfResult.getZeroKnowledgeProof().getRepresentation());
                String g1xJSON = jsonConverter.serialize(g1x.getRepresentation());
                String credentialJSON = jsonConverter.serialize(credential.getRepresentation());
                String dleqChallengeJSON = jsonConverter.serialize(dleqProof.getChallenge().getRepresentation());
                String dleqResponseJSON = jsonConverter.serialize(dleqProof.getResponse().getRepresentation());

                String dittorProofString = buildDittorProofLine(context, realPkJSON, realNymJSON, realVrfZkpJSON,
                        g1xJSON, credentialJSON, dleqChallengeJSON, dleqResponseJSON);
                printProofSummary(nodeName, context, realPkJSON, realNymJSON, realVrfZkpJSON, g1xJSON,
                        credentialJSON, dleqChallengeJSON, dleqResponseJSON);

                String nodePath;
                if (nodesEnv == null || nodesEnv.trim().isEmpty()) {
                    nodePath = System.getenv().getOrDefault("DITTOR_PROOF_PATH",
                        "../chutney/net/nodes/000a/dittor_proof.txt");
                } else if (dataDir != null && !dataDir.trim().isEmpty()) {
                    nodePath = dataDir + "/nodes/" + nodeName + "/dittor_proof.txt";
                } else {
                    nodePath = "../chutney/net/nodes/" + nodeName + "/dittor_proof.txt";
                }

                writeFileAtomically(nodePath, dittorProofString);
                System.out.println("Successfully exported proof to Chutney node " + nodeName + "!");

                // Payload no formato esperado pela bridge
                String familyIdsBridge = "-";
                String bridgePayload = buildBridgePayloadLine(context, realPkJSON, realNymJSON, realVrfZkpJSON,
                        g1xJSON, credentialJSON, dleqChallengeJSON, dleqResponseJSON, nodeName, familyIdsBridge);

                String bridgePayloadPath = nodePath.replace("dittor_proof.txt", "bridge_payload.txt");
                writeFileAtomically(bridgePayloadPath, bridgePayload);
                System.out.println("Successfully exported bridge payload for node " + nodeName + " to "
                        + bridgePayloadPath);
            } catch (Exception e) {
                System.out.println("[DITTOR CONFIG] (" + nodeName + ") Error compiling tokens: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

}
