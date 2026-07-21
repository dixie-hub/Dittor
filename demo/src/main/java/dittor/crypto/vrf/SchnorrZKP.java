package dittor.crypto.vrf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class SchnorrZKP {
    private final Zn zp;
    private final GroupElement g2;

    public SchnorrZKP(BilinearGroup pairing) {
        this.zp = pairing.getZn();
        this.g2 = pairing.getG2().getGenerator();
    }

    public Proof generateProof(Zn.ZnElement secretX, GroupElement userPubKeyG2, String context) {
        Zn.ZnElement blindingFactor = zp.getUniformlyRandomElement();

        GroupElement commitment = g2.pow(blindingFactor).compute();

        Zn.ZnElement challenge = hashChallenge(userPubKeyG2, commitment, context);

        Zn.ZnElement response = blindingFactor.add(challenge.mul(secretX));

        return new Proof(challenge, response);
    }

    public boolean verifyProof(GroupElement userPubKeyG2, String context, Proof proof) {
        // commitment reconstruction reconstruct = g2^response * (userPubKeyG2)^(-challenge)
        GroupElement commitmentReconstruct = g2.pow(proof.getResponse()).op(userPubKeyG2.pow(proof.getChallenge()).inv()).compute();

        Zn.ZnElement challengeReconstruct = hashChallenge(userPubKeyG2, commitmentReconstruct, context);

        return proof.getChallenge().equals(challengeReconstruct);
    }

    private Zn.ZnElement hashChallenge(GroupElement pk, GroupElement commitment, String context) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            digest.update(pk.getUniqueByteRepresentation());
            digest.update(commitment.getUniqueByteRepresentation());
            digest.update(context.getBytes(StandardCharsets.UTF_8));
            
            byte[] hashBytes = digest.digest();
            BigInteger val = new BigInteger(1, hashBytes);
            return zp.valueOf(val);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash the challenge from the Schnorr's ZKP", e);
        }
    }
}