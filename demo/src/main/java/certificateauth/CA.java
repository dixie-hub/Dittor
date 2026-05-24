package certificateauth;
/*Classe para as Certificate Authorities que vão comunicar entre si para produzirem uma assinatura por cima de um atributo de um user 

Responsabilidades:
- Emitir credenciais (assinaturas por cima dos atributos)
- Garantir unicidade de users (ser sybil-resistant)
- Guardar memória dos users
- Threshold issuance?

Setup:
- gera(chavepriv, chavepub), para comunicar com outras CAs e com os users
- envia chavepub para todos (Diffie-Hellman?)
*/
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CA {
    public int caID;
    private Zn.ZnElement secretKeyShare; //share for the master key
    private GroupElement masterPubKey;

    public CA(int id) {
        this.caID = id;
    }

    public void setKeyShare(Zn.ZnElement skShare, GroupElement mpk) {
        this.secretKeyShare = skShare;
        this.masterPubKey = mpk;
    }

    public GroupElement issueSignatureShare(GroupElement blindedCommit) {
        //blind signing: share = commitment ^ skShare
        return blindedCommit.pow(secretKeyShare).compute();
    }
}
