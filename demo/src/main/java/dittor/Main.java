package dittor;

import java.io.FileWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
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

        // pergunta a mpk a uma CA que já esteja pronta, e repete até o DKG estar finalizado
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

        // Setup User Node on port 8050
        System.out.println("Starting User node on port 8050...");
        User cryptoUser = new User(pairing);
        
        UserProtocol userProtocol = new UserProtocol(pairing, cryptoUser, t, vrf, schnorr, dleqZKP, g1, h1, mpkG1, mpkG2, g1,
                g2, "000a", new ArrayList<>());
        Properties userProperties = new Properties();
        userProperties.setProperty("address", localhost);
        userProperties.setProperty("port", "8050");

        babel.registerProtocol(userProtocol);
        userProtocol.init(userProperties);
        userProtocol.start();

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
        // 4. TRIGGER PROTOCOL EXECUTION
        // ---------------------------------------------------------
        System.out.println("Triggering User Protocol to begin network handshake...");
        userProtocol.startRegistration(caNetworkMap, daHost);

        Thread.sleep(2500); // to make sure the protocol async tasks are complete
        try {
            JSONConverter jsonConverter = new JSONConverter();

            String context = "TorRelayConsensus2026";

            GroupElement userPubKey = cryptoUser.getPublicKeyG2();
            VRFResult vrfResult = cryptoUser.generateVRFPseudonym(vrf, context);
            Proof identityZKP = cryptoUser.generateSchnorrPoK(schnorr, context);

            String realPkJSON = jsonConverter.serialize(userPubKey.getRepresentation());
            String realNymJSON = jsonConverter.serialize(vrfResult.getPseudonym().getRepresentation());
            String realVrfZkpJSON = jsonConverter.serialize(vrfResult.getZeroKnowledgeProof().getRepresentation());

            String realProofChallengeString = jsonConverter.serialize(identityZKP.getChallenge().getRepresentation());
            String realProofResponseString = jsonConverter.serialize(identityZKP.getResponse().getRepresentation());

            String dittorProofString = "dittor-proof " + context + " " + realPkJSON + " " + realNymJSON + " "
                    + realVrfZkpJSON + " " + realProofChallengeString + " " + realProofResponseString;
            System.out.println("\n=======================================");
            System.out.println("[DITTOR CONFIG] " + dittorProofString);
            System.out.println("=======================================\n");

            String chutneyPath = System.getenv().getOrDefault("DITTOR_PROOF_PATH",
                    "../chutney/net/nodes/000a/dittor_proof.txt");
            FileWriter writer = new FileWriter(chutneyPath);
            writer.write(dittorProofString);
            writer.close();
            System.out.println("Successfully exported proof to Chutney node 000a!");
        } catch (Exception e) {
            System.out.println("[DITTOR CONFIG] Error compiling tokens: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
