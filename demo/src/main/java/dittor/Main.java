package dittor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

public class Main {

    public static void main(String[] args) {
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

        System.out.println("Running DKG protocol with " + t + "-of-" + n + " threshold protocol for CAs...");

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

        for (int i = 0; i < n; i++) {
            CA current = CAs.get(i);
            List<Zn.ZnElement> shares = allCollectedShares.get(i);
            current.finalizeDKG(shares, pkG1s, pkG2s);
        }

        System.out.println("CAs with threshold keys!");

        User user = new User(pairing);

        System.out.println("User generating blinded commitment...");
        GroupElement commitment = user.createBlindedCommit(g1, h1); // random point based on user info

        System.out.println("User is collecting " + t + " signatures shares from the CAs...");
        List<GroupElement> gatheredShares = new ArrayList<>();
        List<Integer> signerIDs = new ArrayList<>();

        for (int i = 0; i < t; i++) {
            CA selectedCA = CAs.get(i);
            gatheredShares.add(selectedCA.issueSignatureShare(commitment));
            signerIDs.add(selectedCA.caID);
        }

        System.out.println("User is aggregating the shares received...");
        GroupElement aggregatedBlindedSignature = user.aggregateShares(gatheredShares, signerIDs);

        GroupElement mpkG1 = CAs.get(0).getMasterPubKeyG1();
        GroupElement mpkG2 = CAs.get(0).getMasterPubKeyG2();

        System.out.println("User is unblinding the aggregated signature...");
        GroupElement finalCredential = user.unblindSignature(aggregatedBlindedSignature, mpkG1);

        System.out.println("Verifying if the final credencial is valid...");
        boolean isValid = user.verifyCredential(finalCredential, mpkG2, g1, g2);
        if (isValid) {
            System.out.println("User successfully signed its attributes!");

            System.out.println("\n--- Initiating SASSI protocol ---");

            DodisYampolskiyVRF dyVRF = new DodisYampolskiyVRF(pairing);
            SchnorrZKP schnorrZKP = new SchnorrZKP(pairing);
            String context = "TorRelay";

            System.out.println("User is calculating VRF pseudonym for context: '" + context + "'...");
            VRFResult vrf = user.generateVRFPseudonym(dyVRF, context);

            System.out.println("User generating Zero-Knowledge Proof of matching identities between VRF and signed identity...");
            Proof proofOfKnowledge = user.generateSchnorrPoK(schnorrZKP, context);

            System.out.println("Simulation of DA behaviour to be implemented in Rust--TODO");

            boolean isZKPValid = schnorrZKP.verifyProof(user.getPublicKeyG2(), context, proofOfKnowledge);
            System.out.println("Zero-Knowledge Proof Validity: " + isZKPValid);

            boolean isVRFValid = dyVRF.isValid(user.getPublicKeyG2(), context, vrf);
            System.out.println("VRF Proof validity: " + isVRFValid);

            Set<GroupElement> activeNyms = new HashSet<>();

            if (isZKPValid && isVRFValid) {
                System.out.println("Cryptographic verification was successfull");
                System.out.println("DA behaviour in the Tor Consensus docs, to be implemented in Rust--TODO");

                GroupElement pseudonym = vrf.getPseudonym();
                if (!activeNyms.contains(pseudonym)) {
                    activeNyms.add(pseudonym);
                    System.out.println("Pseudonym added to Tor Consensus!");
                } 

                // just to check if it detects sybil attacks
                System.out.println("Possible Sybil Attack!!");
                GroupElement sybil = user.generateVRFPseudonym(dyVRF, context).getPseudonym();
                Proof sybilProof = user.generateSchnorrPoK(schnorrZKP, context);

                boolean isSybilZKPValid = schnorrZKP.verifyProof(user.getPublicKeyG2(), context, sybilProof);

                if (isSybilZKPValid && activeNyms.contains(sybil)) 
                    System.out.println("Sybil attack detected by: " + sybil + "!!");
            }
        }
        else
            System.out.println("The credential obtained by the user is not valid.");
    }

}
