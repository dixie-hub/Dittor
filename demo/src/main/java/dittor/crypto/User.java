package dittor.crypto;
/*Classe para os utilizadores que vão enviar um atributo para ser assinado pelas CAs e vao criar um pseudonimo para enviar para as DAs do Tor */

import java.util.List;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import dittor.crypto.vrf.DodisYampolskiyVRF;
import dittor.crypto.vrf.Proof;
import dittor.crypto.vrf.SchnorrZKP;
import dittor.crypto.vrf.VRFResult;

public class User {

    private Zn.ZnElement secretX;
    private Zn.ZnElement blindingFactor;
    private BilinearGroup pairing;
    private GroupElement publicKeyG2;

    public User(BilinearGroup pairing) {
        this.pairing = pairing;
        Zn zp = pairing.getZn();

        this.secretX = zp.getUniformlyRandomElement(); // user secret identity
        this.publicKeyG2 = pairing.getG2().getGenerator().pow(secretX).compute(); // user pubKey
        this.blindingFactor = zp.getUniformlyRandomElement();
    }

    public GroupElement getPublicKeyG2() {
        return this.publicKeyG2;
    }

    public VRFResult generateVRFPseudonym(DodisYampolskiyVRF vrf, String context) {
        return vrf.buildProof(this.secretX, context);
    }

    public GroupElement createBlindedCommit(GroupElement g, GroupElement h) {
        return g.pow(secretX).op(h.pow(blindingFactor)).compute(); // Pedersen Commitment = (g^secretX) *
                                                                   // (h^blindingFactor)
    }

    public Proof generateSchnorrPoK(SchnorrZKP schnorrZKP, String context) {
        return schnorrZKP.generateProof(this.secretX, this.publicKeyG2, context);
    }

    public GroupElement aggregateShares(List<GroupElement> sigShares, List<Integer> signerIDs) {
        Zn zp = pairing.getZn();
        GroupElement aggregatedSignature = pairing.getG1().getNeutralElement();

        for (int i = 0; i < sigShares.size(); i++) {
            int currentID = signerIDs.get(i);
            GroupElement share = sigShares.get(i);

            Zn.ZnElement numerator = zp.getOneElement();
            Zn.ZnElement denominator = zp.getOneElement();

            for (int j : signerIDs) {
                if (j == currentID) continue;
                
                Zn.ZnElement valueJ = zp.valueOf(j);
                Zn.ZnElement valueI = zp.valueOf(currentID);

                numerator = numerator.mul(valueJ.neg()); // 0-j = -j
                denominator = denominator.mul(valueI.sub(valueJ)); // i - j
            }

            // lambda = numerator / denominator
            Zn.ZnElement lambda = numerator.mul(denominator.inv());

            // recombine share: aggregated = aggregated * (share ^ lambda)
            GroupElement term = share.pow(lambda);
            aggregatedSignature = aggregatedSignature.op(term);
        }

        return aggregatedSignature.compute();
    }

    public GroupElement unblindSignature(GroupElement aggregatedBlindedSignature, GroupElement masterPubKey) {
        GroupElement res = masterPubKey.pow(blindingFactor).compute(); // mpk is h_1^msk, so res = h_1^(r*msk)

        // g_1^(x*msk) * h_1^(r*msk) * h_1^(-r*msk) = g_1^(x*msk)
        // g_1^(x*msk) is the unblinded credential
        return aggregatedBlindedSignature.op(res.inv()).compute();
    }

    public boolean verifyCredential(GroupElement unblindedSignature, GroupElement mpk, GroupElement g1,
            GroupElement g2) {
        // bilinear property in pairing function => e(A^a,B^b) = e(A, B)^ab

        // e(g_1^(x*msk),g_2) = e(g1,g2)^(x*msk)
        GroupElement leftSide = pairing.getBilinearMap().apply(unblindedSignature, g2).compute();

        // e(g_1^x,mpk_g2) = e(g_1^x,g_2^msk) = e(g_1,g_2)^(x*msk)
        GroupElement rightSide = pairing.getBilinearMap().apply(g1.pow(secretX), mpk).compute();

        return leftSide.equals(rightSide); // validates they are equal without disclosing user's identity, x
    }
}
