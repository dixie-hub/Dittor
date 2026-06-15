package dittor.crypto;

import org.cryptimeleon.math.structures.groups.GroupElement;

import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.VRFResult;

/* Classe para as Directory Authorities do Tor

Responsaveis por:
- Validar pseudonimos que os utilizadores enviam
 */

public class DA {

    public DA() {

    }

    public boolean verifyVrf(VRFResult vrfData, String context) {
        System.out.println("[DA-Crypto-Stub] Bypassing VRF verification check"); 
        return true;
    }

    public boolean verifyIdentityProof(GroupElement userPubKeyG2, Proof identityProof, String context) {
        System.out.println("[DA-Crypto-Stub] Bypassing Schnorr identity ZKP check");
        return true;
    }

}
