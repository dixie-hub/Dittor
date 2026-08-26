package dittor.crypto;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cryptimeleon.math.structures.groups.GroupElement;

import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.SchnorrZKP;
import dittor.crypto.vrf.VRFResult;

/* Classe para as Directory Authorities do Tor
 * Responsáveis por: Validar pseudónimos que os utilizadores enviam
 */
public class DA {

    private final DodisYampolskiyVRF dodisYampolskiy;
    private final SchnorrZKP schnorr;

    // (context, pseudónimo) -> (nodeId -> family_ids desse nó)
    private final Map<String, Map<String, Set<String>>> registrations = new HashMap<>();

    public DA(DodisYampolskiyVRF dodisYampolskiy, SchnorrZKP schnorr) {
        this.dodisYampolskiy = dodisYampolskiy;
        this.schnorr = schnorr;
    }

    public boolean verifyVrf(GroupElement userPubKeyG2, VRFResult vrfData, String context) {
        System.out.println("[DA-Crypto] Running Dodis-Yampolskiy VRF validation checks...");

        try {
            boolean isValid = dodisYampolskiy.isValid(userPubKeyG2, context, vrfData);
            System.out.println("[DA-Crypto] VRF Evaluation Outcome: " + (isValid ? "PASS" : "FAIL"));
            return isValid;
        } catch (Exception e) {
            System.err.println("[DA-Crypto] VRF validation failed: " + e.getMessage());
            return false;
        }
    }

    public boolean verifyIdentityProof(GroupElement userPubKeyG2, Proof identityProof, String context) {
        System.out.println("[DA-Crypto] Verifying Schnorr Non-Interactive Zero-Knowledge Proof...");

        try {
            boolean isValid = schnorr.verifyProof(userPubKeyG2, context, identityProof);
            System.out.println("[DA-Crypto] Schnorr ZKP Evaluation Outcome: " + (isValid ? "PASS" : "FAIL"));
            return isValid;
        } catch (Exception e) {
            System.err.println("[DA-Crypto] Schnorr ZKP validation failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static String pseudonymKey(String context, GroupElement pseudonym) {
        byte[] raw = pseudonym.getUniqueByteRepresentation();
        StringBuilder builder = new StringBuilder();
        for (byte b : raw) builder.append(String.format("%02x", b));
        return context + "|" + builder;
    }

    public synchronized boolean registerNode(String context, GroupElement pseudonym, String nodeId, Set<String> familyIds) {
        String key = pseudonymKey(context, pseudonym);
        Map<String, Set<String>> existing = registrations.get(key);

        if (existing == null) {
            Map<String, Set<String>> entry = new HashMap<>();
            entry.put(nodeId, familyIds);
            registrations.put(key, entry);
            System.out.println("[DA] New pseudonym registered for node " + nodeId);
            return true;
        }
        if (existing.containsKey(nodeId))
            return true;
        Set<String> knownFamilyIds = new HashSet<>();
        for (Set<String> ids : existing.values())
            knownFamilyIds.addAll(ids);

        boolean sharesFamily = !Collections.disjoint(knownFamilyIds, familyIds);
        if (!sharesFamily) {
            System.out.println("[DA] REJECTED: node " + nodeId + " reused a pseudonym without shared family ids");
            return false;
        }

        existing.put(nodeId, familyIds);
        System.out.println("[DA] Node " + nodeId + " accepted under existing pseudonym (shared family)!");
        return true;
    }
}