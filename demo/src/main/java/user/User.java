package user;
/*Classe para os utilizadores que vão enviar um atributo para ser assinado pelas CAs e vao criar um pseudonimo para enviar para as DAs do Tor */

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class User {

    private Zn.ZnElement secretX;
    private Zn.ZnElement blindingFactor;
    private BilinearGroup pairing;

    public User(BilinearGroup pairing) {
        this.pairing = pairing;
        Zn zp = pairing.getZn();

        this.secretX = zp.getUniformlyRandomElement();
        this.blindingFactor = zp.getUniformlyRandomElement();
    }

    public GroupElement createBlindedCommit(GroupElement g, GroupElement h) {
        return g.pow(secretX).op(h.pow(blindingFactor)).compute(); // commitment = (g^x) * (h^r)
    }

    public GroupElement aggregateShares(GroupElement sigShare1, GroupElement sigShare2) {
        Zn zp = pairing.getZn();

        Zn.ZnElement L1 = zp.valueOf(2);
        Zn.ZnElement L2 = zp.valueOf(-1);

        //aggregated signature = (Share1 ^ L1) * (Share2 ^ L2)
        GroupElement aggregatedSignature = sigShare1.pow(L1).op(sigShare2.pow(L2)).compute();

        return aggregatedSignature;
    }
}
