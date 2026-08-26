package dittor.crypto.vrf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class DLEQZKP {
    private final Zn zp;
    private final GroupElement g1;
    private final GroupElement g2;

    public DLEQZKP(BilinearGroup pairing) {
        this.zp = pairing.getZn();
        this.g1 = pairing.getG1().getGenerator();
        this.g2 = pairing.getG2().getGenerator();
    }

    public Proof generateProof(Zn.ZnElement secretX, GroupElement g1x, GroupElement pk, String context) {
        Zn.ZnElement k = zp.getUniformlyRandomElement();

        GroupElement r1 = g1.pow(k).compute();
        GroupElement r2 = g2.pow(k).compute();

        Zn.ZnElement challenge = hashChallenge(g1x, pk, r1, r2, context);
        Zn.ZnElement response = k.add(challenge.mul(secretX));

        return new Proof(challenge, response);
    }

    public boolean verifyProof(GroupElement g1x, GroupElement pk, String context, Proof proof) {
        GroupElement r1Reconstruct = g1.pow(proof.getResponse()).op(g1x.pow(proof.getChallenge()).inv()).compute();
        GroupElement r2Reconstruct = g2.pow(proof.getResponse()).op(pk.pow(proof.getChallenge()).inv()).compute();

        Zn.ZnElement challengeReconstruct = hashChallenge(g1x, pk, r1Reconstruct, r2Reconstruct, context);

        return proof.getChallenge().equals(challengeReconstruct);
    }

    private Zn.ZnElement hashChallenge(GroupElement g1x, GroupElement pk, GroupElement r1, GroupElement r2, String context) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            digest.update(g1x.getUniqueByteRepresentation());
            digest.update(pk.getUniqueByteRepresentation());
            digest.update(r1.getUniqueByteRepresentation());
            digest.update(r2.getUniqueByteRepresentation());
            digest.update(context.getBytes(StandardCharsets.UTF_8));

            byte[] hashBytes = digest.digest();
            BigInteger val = new BigInteger(1, hashBytes);
            return zp.valueOf(val);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash the challenge from the DLEQ ZKP", e);
        }
    }
}
