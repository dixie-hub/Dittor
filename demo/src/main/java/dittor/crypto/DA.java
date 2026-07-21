package dittor.crypto;

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
}