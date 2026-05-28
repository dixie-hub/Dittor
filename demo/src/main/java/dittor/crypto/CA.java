package dittor.crypto;

import java.util.ArrayList;
import java.util.List;

/*Classe para as Certificate Authorities que vão comunicar entre si para produzirem uma assinatura por cima de um atributo de um user 

Responsabilidades:
- Emitir credenciais (assinaturas por cima dos atributos)
- Garantir unicidade de users (ser sybil-resistant)
- Guardar memória dos users
- Threshold issuance

Setup:
- gera(chavepriv, chavepub), para comunicar com outras CAs e com os users
- envia chavepub para todos (Diffie-Hellman?)
*/
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CA {
    public int caID;
    private Zn zp;

    /* // atributos secretos da polinomial usada, neste caso uma reta
    // (f_i(x) = a1 * x + a0)
    private Zn.ZnElement a0; // interceção com o eixo do y, f(0)
    private Zn.ZnElement a1; // declive da polinomial usada pela CA */
    private List<Zn.ZnElement> coefficients;

    // chaves depois de DKG
    private Zn.ZnElement secretKeyShare; // share for the master key
    private GroupElement masterPubKeyG1; // key for unblinding
    private GroupElement masterPubKeyG2; // key for verification

    public CA(int id, BilinearGroup pairing) {
        this.caID = id;
        this.zp = pairing.getZn();
    }

    public void generatePrivatePolynomial(int threshold) {
        coefficients = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            coefficients.add(zp.getUniformlyRandomElement());
        }
    }

    // f(x) = a0 + a1*x + a2*(x^2) + ... + a_{t-1}*(x^{t-1})
    public Zn.ZnElement evaluatePolynomial(int recipientCaID) {
        Zn.ZnElement result = zp.getZeroElement(); 
        Zn.ZnElement xPower = zp.getOneElement(); // x^i, so x^1 = x
        Zn.ZnElement x = zp.valueOf(recipientCaID);

        for (Zn.ZnElement coefficient : coefficients) {
            result = result.add(coefficient.mul(xPower));
            xPower = xPower.mul(x);
        }
        return result;
    }

    public GroupElement getPublicKey(GroupElement basePoint) {
        return basePoint.pow(coefficients.get(0)).compute();
    }

    public void finalizeDKG(List<Zn.ZnElement> receivedShares, List<GroupElement> pkG1s, List<GroupElement> pkG2s) {
        // sum key shares from all CAs including itself to create final secret key share
        this.secretKeyShare = zp.getZeroElement();
        for (Zn.ZnElement share : receivedShares) {
            this.secretKeyShare = this.secretKeyShare.add(share);
        }

        // multiply all individual pubKeys to create master pubKey
        this.masterPubKeyG1 = pkG1s.get(0).getStructure().getNeutralElement();
        for (GroupElement pk : pkG1s) {
            this.masterPubKeyG1 = this.masterPubKeyG1.op(pk).compute();
        }

        this.masterPubKeyG2 = pkG2s.get(0).getStructure().getNeutralElement();
        for (GroupElement pk : pkG2s) {
            this.masterPubKeyG2 = this.masterPubKeyG2.op(pk).compute();
        }

        // clean up de atributos sensíveis
        this.coefficients = null;
    }

    public GroupElement issueSignatureShare(GroupElement blindedCommit) {
        // blind signing: share = commitment ^ skShare
        return blindedCommit.pow(secretKeyShare).compute();
    }

    public GroupElement getMasterPubKeyG1() {
        return masterPubKeyG1;
    }

    public GroupElement getMasterPubKeyG2() {
        return masterPubKeyG2;
    }
}
