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
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import dittor.crypto.CA;
import dittor.crypto.DA;
import dittor.crypto.User;
import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.SchnorrZKP;
import dittor.crypto.vrf.VRFResult;
import dittor.protocols.CAProtocol;
import dittor.protocols.DAProtocol;
import dittor.protocols.UserProtocol;
import dittor.tor.DAServer;
import pt.unl.fct.di.novasys.babel.core.Babel;
import pt.unl.fct.di.novasys.network.data.Host;

public class Main {

    public static void main(String[] args) throws Exception {

        // ---------------------------------------------------------
        // 1. CRYPTOGRAPHIC SETUP (Simulating a Trusted Dealer phase)
        // ---------------------------------------------------------

        // threshold t and CAs pool size n
        int t = 2;
        int n = 3;

        System.out.println("Initializing Bilinear Group...");
        BilinearGroup pairing = new BarretoNaehrigBilinearGroup(100); // eliptic curve with 100 bits security parameter
        // Zn zp = pairing.getZn(); // scalar field containing all the big integers
        // modulo the prime order p of the curve

        // random points selected from G1 generator, acting as bases for exponents for
        // Pedersen Commitment
        GroupElement g1 = pairing.getG1().getGenerator();
        GroupElement h1 = pairing.getG1().getUniformlyRandomElement().compute();
        GroupElement g2 = pairing.getG2().getGenerator();

        System.out.println("Running DKG protocol with " + t + "-of-" + n + " threshold for CAs...");

        // Se o threshold é no mínimo 2 de três, guarda-se o segredo num polinómio de
        // grau 1, ou seja uma linha: f(x) = a1*x + a0
        System.out.println("Initializing " + n + " CAs...");
        List<CA> CAs = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            CAs.add(new CA(i, pairing));
        }

        // CAs generate their own polynomial
        for (CA ca : CAs)
            ca.generatePrivatePolynomial(t);

        // CAs broadcast public keys to each other
        List<GroupElement> pkG1s = new ArrayList<>();
        List<GroupElement> pkG2s = new ArrayList<>();
        for (CA ca : CAs) {
            pkG1s.add(ca.getPublicKey(h1));
            pkG2s.add(ca.getPublicKey(g2));
        }

        // CAs send polynomial evaluations to each other
        // ex. CA 1 receives f1(1) from itself, f2(1) from CA 2, and f3(1) from CA 3
        // synchronized broadcast exchange
        List<List<Zn.ZnElement>> allCollectedShares = new ArrayList<>();
        for (CA recipientCA : CAs) {
            List<Zn.ZnElement> sharesForThisCA = new ArrayList<>();
            for (CA senderCA : CAs) {
                sharesForThisCA.add(senderCA.evaluatePolynomial(recipientCA.caID));
            }
            allCollectedShares.add(sharesForThisCA);
        }

        for (int i = 0; i < n; i++)
            CAs.get(i).finalizeDKG(allCollectedShares.get(i), pkG1s, pkG2s);

        System.out.println("DKG Complete. Master keys established.");

        // ---------------------------------------------------------
        // Initializing Dodis-Yampolskiy and Schnorr engines
        // ---------------------------------------------------------

        DodisYampolskiyVRF vrf = new DodisYampolskiyVRF(pairing);
        SchnorrZKP schnorr = new SchnorrZKP(pairing);

        // ---------------------------------------------------------
        // 2. BABEL NETWORK
        // ---------------------------------------------------------

        System.out.println("\n--- Initializing Babel Network Framework ---");
        Babel babel = Babel.getInstance();
        String localhost = InetAddress.getByName("127.0.0.1").getHostAddress();

        // Setup DA on port 9000
        System.out.println("Starting DA node on port 9000");
        DA cryptoDA = new DA(vrf, schnorr);
        DAProtocol daProtocol = new DAProtocol(pairing, cryptoDA);
        Properties daProperties = new Properties();
        daProperties.setProperty("address", localhost);
        daProperties.setProperty("port", "9000");
        Host daHost = new Host(InetAddress.getByName(localhost), 9000);

        babel.registerProtocol(daProtocol);
        daProtocol.init(daProperties);

        // Setup CA on ports 9001, 9002, 9003...
        Map<Host, Integer> caNetworkMap = new HashMap<>();
        int caBasePort = 9000;

        for (int i = 0; i < n; i++) {
            int caPort = caBasePort + CAs.get(i).caID;
            System.out.println("Starting CA-" + CAs.get(i).caID + " node on port " + caPort + "...");

            CAProtocol caProtocol = new CAProtocol(pairing, CAs.get(i), CAs.get(i).caID);
            Properties caProps = new Properties();
            caProps.setProperty("address", localhost);
            caProps.setProperty("port", String.valueOf(caPort));

            Host caHost = new Host(InetAddress.getByName(localhost), caPort);
            caNetworkMap.put(caHost, CAs.get(i).caID);

            babel.registerProtocol(caProtocol);
            caProtocol.init(caProps);
        }

        // Setup User Node on port 8050
        System.out.println("Starting User node on port 8050...");
        User cryptoUser = new User(pairing);
        GroupElement mpkG1 = CAs.get(0).getMasterPubKeyG1(); // master keys from DKG phase
        GroupElement mpkG2 = CAs.get(0).getMasterPubKeyG2();

        UserProtocol userProtocol = new UserProtocol(pairing, cryptoUser, t, vrf, schnorr, g1, h1, mpkG1, mpkG2, g1,
                g2);
        Properties userProperties = new Properties();
        userProperties.setProperty("address", localhost);
        userProperties.setProperty("port", "8050");

        babel.registerProtocol(userProtocol);
        userProtocol.init(userProperties);

        // Start Babel
        babel.start();
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

            String chutneyPath = System.getenv().getOrDefault("CHUTNEY_PATH",
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
