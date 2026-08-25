package dittor.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.cryptimeleon.math.serialization.converter.JSONConverter;
/*Classe para as Certificate Authorities que vão comunicar entre si para produzirem uma assinatura por cima de um atributo de um user 

Responsabilidades:
- Emitir credenciais (assinaturas por cima dos atributos)
- Garantir unicidade de users (ser sybil-resistant)
- Guardar memória dos users
- Threshold issuance

DKG: Pedersen VSS com a correção de Gennaro et al. (hash-then-reveal + verificação de shares)
*/
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CA {
    public int caID;
    private Zn zp;

    // f_i(x) = secretCoefficients[0] + secretCoefficients[1]*x + ... (polinómio do segredo)
    private List<Zn.ZnElement> secretCoefficients;
    // f'_i(x), polinómio de blinding do Pedersen VSS, mesmo grau de f_i 
    private List<Zn.ZnElement> blindingCoefficients;

    // C_{i,k} = g1^{a_k} * h1^{b_k}. k = 0...t-1, só conhecidos localmente até revealCommitments()
    private List<GroupElement> commitmentsG1;
    private GroupElement plainPubKeyG1; // h1^{a_0}
    private GroupElement plainPubKeyG2; // g2^{a_0}

    private boolean disqualified = false;

    // chaves depois de DKG
    private Zn.ZnElement secretKeyShare; // share for the master key
    private GroupElement masterPubKeyG1; // key for unblinding
    private GroupElement masterPubKeyG2; // key for verification

    public CA(int id, BilinearGroup pairing) {
        this.caID = id;
        this.zp = pairing.getZn();
    }

    public void generatePrivatePolynomial(int threshold) {
        secretCoefficients = new ArrayList<>();
        blindingCoefficients = new ArrayList<>();
        for (int i = 0; i < threshold; i++) {
            secretCoefficients.add(zp.getUniformlyRandomElement());
            blindingCoefficients.add(zp.getUniformlyRandomElement());
        }
    }

    // Fase 1 da solução de Gennaro et al. - cálculo dos compromissos de Pedersen localmente, sem os publicar
    public void computeCommitments(GroupElement g1, GroupElement h1, GroupElement g2) {
        commitmentsG1 = new ArrayList<>();
        for (int k = 0; k < secretCoefficients.size(); k++) {
            GroupElement c = g1.pow(secretCoefficients.get(k)).op(h1.pow(blindingCoefficients.get(k))).compute();
            commitmentsG1.add(c);
        }
        plainPubKeyG1 = h1.pow(secretCoefficients.get(0)).compute();
        plainPubKeyG2 = g2.pow(secretCoefficients.get(0)).compute();
    }

    // Primeira publicação da solução de Gennaro et al., sem os compromissos, só o hash
    public String getCommitmentHash() {
        return hashCommitments(commitmentsG1, plainPubKeyG1, plainPubKeyG2);
    }

    // Segunda publicação, depois de todos os hashes serem divulgados
    public List<GroupElement> getRevealedCommitments() {
        return commitmentsG1;
    }

    public GroupElement getRevealedPubKeyG1() {
        return plainPubKeyG1;
    }

    public GroupElement getRevealedPubKeyG2() {
        return plainPubKeyG2;
    }

    public static String hashCommitments(List<GroupElement> commitments, GroupElement pubKeyG1, GroupElement pubKeyG2) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            JSONConverter jsonConverter = new JSONConverter();
            for (GroupElement c : commitments) {
                digest.update(jsonConverter.serialize(c.getRepresentation()).getBytes(StandardCharsets.UTF_8));
            }
            digest.update(jsonConverter.serialize(pubKeyG1.getRepresentation()).getBytes(StandardCharsets.UTF_8));
            digest.update(jsonConverter.serialize(pubKeyG2.getRepresentation()).getBytes(StandardCharsets.UTF_8));
            byte[] hashBytes = digest.digest();
            StringBuilder builder = new StringBuilder();
            for (byte b : hashBytes) builder.append(String.format("%02x", b));
            return builder.toString();
        } catch (Exception e) {
            throw new RuntimeException("ERROR: Failed to hash DKG commitments!", e);
        }
    }

    public Zn.ZnElement evaluateSecretPolynomial(int recipientCaID) {
        return evaluatePolynomial(secretCoefficients, recipientCaID);
    }

    public Zn.ZnElement evaluateBlindingPolynomial(int recipientCaID) {
        return evaluatePolynomial(blindingCoefficients, recipientCaID);
    }

    private Zn.ZnElement evaluatePolynomial(List<Zn.ZnElement> coefficients, int recipientCaID) {
        Zn.ZnElement result = zp.getZeroElement(); 
        Zn.ZnElement xPower = zp.getOneElement();
        Zn.ZnElement x = zp.valueOf(recipientCaID);

        for (Zn.ZnElement coefficient : coefficients) {
            result = result.add(coefficient.mul(xPower));
            xPower = xPower.mul(x);
        }
        return result;
    }

    // Verificação do share: g1^(s_ij) * h1^(t_ij) == n_k C_(i,k)^(myID^k)
    public static boolean verifyShare(Zn.ZnElement s_ij, Zn.ZnElement t_ij, List<GroupElement> senderCommitments, int myID, GroupElement g1, GroupElement h1, Zn zp) {
        GroupElement leftHandSide = g1.pow(s_ij).op(h1.pow(t_ij)).compute();
        GroupElement rightHandSide = senderCommitments.get(0).getStructure().getNeutralElement();
        Zn.ZnElement xPower = zp.getOneElement();
        Zn.ZnElement x = zp.valueOf(myID);
        for (GroupElement c : senderCommitments) {
            rightHandSide = rightHandSide.op(c.pow(xPower)).compute();
            xPower = xPower.mul(x);
        }
        return leftHandSide.equals(rightHandSide);
    }

    public void disqualify() {
        this.disqualified = true;
    }

    public boolean isDisqualified() {
        return disqualified;
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
        this.secretCoefficients = null;
        this.blindingCoefficients = null;
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
