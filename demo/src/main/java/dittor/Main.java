package dittor;

import java.io.FileWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup.GroupChoice;

import dittor.crypto.DA;
import dittor.crypto.User;
import dittor.crypto.vrf.DLEQZKP;
import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.SchnorrZKP;
import dittor.crypto.vrf.VRFResult;
import dittor.protocols.DAProtocol;
import dittor.protocols.MasterPubKeyFetcher;
import dittor.protocols.UserProtocol;
import dittor.tor.DAServer;
import pt.unl.fct.di.novasys.babel.core.Babel;
import pt.unl.fct.di.novasys.network.data.Host;

public class Main {

    public static void main(String[] args) throws Exception {

        // ---------------------------------------------------------
        // 1. CRYPTOGRAPHIC SETUP
        // ---------------------------------------------------------

        int t = 2;
        int n = 3;

        System.out.println("Initializing Bilinear Group...");
        BilinearGroup pairing = new MclBilinearGroup(GroupChoice.BLS12_381); // BLS12-381 (mclwrap/MCL), 128 bits

        GroupElement g1 = pairing.getG1().getGenerator();
        GroupElement h1 = pairing.getHashIntoG1().hash("Dittor-Pedersen-h1-2026"); // fixo
        GroupElement g2 = pairing.getG2().getGenerator();

        DodisYampolskiyVRF vrf = new DodisYampolskiyVRF(pairing);
        SchnorrZKP schnorr = new SchnorrZKP(pairing);
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
        DA cryptoDA = new DA(vrf, schnorr, dleqZKP, pairing, g1, g2, mpkG2);
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
            UserProtocol userProtocol = new UserProtocol(pairing, cryptoUser, t, vrf, schnorr, dleqZKP, g1, h1, mpkG1,
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

                String dittorProofString = "dittor-proof " + context + " " + realPkJSON + " " + realNymJSON + " "
                        + realVrfZkpJSON + " " + g1xJSON + " " + credentialJSON + " " + dleqChallengeJSON + " "
                        + dleqResponseJSON;
                System.out.println("\n=======================================");
                System.out.println("[DITTOR CONFIG] (" + nodeName + ") " + dittorProofString);
                System.out.println("=======================================\n");

                String nodePath;
                if (nodesEnv == null || nodesEnv.trim().isEmpty()) {
                    nodePath = System.getenv().getOrDefault("DITTOR_PROOF_PATH",
                        "../chutney/net/nodes/000a/dittor_proof.txt");
                } else if (dataDir != null && !dataDir.trim().isEmpty()) {
                    nodePath = dataDir + "/nodes/" + nodeName + "/dittor_proof.txt";
                } else {
                    nodePath = "../chutney/net/nodes/" + nodeName + "/dittor_proof.txt";
                }

                FileWriter writer = new FileWriter(nodePath);
                writer.write(dittorProofString);
                writer.close();
                System.out.println("Successfully exported proof to Chutney node " + nodeName + "!");

                // Payload no formato esperado pela bridge
                String familyIdsBridge = "-";
                String bridgePayload = context + "|" + realPkJSON + "|" + realNymJSON + "|" + realVrfZkpJSON + "|"
                        + g1xJSON + "|" + credentialJSON + "|" + dleqChallengeJSON + "|" + dleqResponseJSON + "|"
                        + nodeName + "|" + familyIdsBridge;

                String bridgePayloadPath = nodePath.replace("dittor_proof.txt", "bridge_payload.txt");
                FileWriter bridgeWriter = new FileWriter(bridgePayloadPath);
                bridgeWriter.write(bridgePayload);
                bridgeWriter.close();
                System.out.println("Successfully exported bridge payload for node " + nodeName + " to "
                        + bridgePayloadPath);
            } catch (Exception e) {
                System.out.println("[DITTOR CONFIG] (" + nodeName + ") Error compiling tokens: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

}
