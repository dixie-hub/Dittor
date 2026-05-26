package vrf;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class DodisYampolskiyVRF {
    private final Zn zp;
    private final GroupElement g1;
    private final GroupElement g2;
    private final GroupElement gpairing; // pairing e(g1,g2)
    private final BilinearMap map;

    public DodisYampolskiyVRF(BilinearGroup pairing) {
        this.zp = pairing.getZn();
        this.g1 = pairing.getG1().getGenerator();
        this.g2 = pairing.getG2().getGenerator();
        this.map = pairing.getBilinearMap();

        this.gpairing = pairing.getBilinearMap().apply(g1, g2).compute();
    }

    public Zn.ZnElement hashContext(String context) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(context.getBytes(StandardCharsets.UTF_8));
            BigInteger val = new BigInteger(1, hashBytes);
            return zp.valueOf(val);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash the context.", e);
        }
    }

    public VRFResult buildProof(Zn.ZnElement secretKey, String context) {
        Zn.ZnElement hashedContext = hashContext(context);

        // exponent: (x + hashedContext)^-1 mod p
        Zn.ZnElement exponent = secretKey.add(hashedContext).inv();

        GroupElement pi = g1.pow(exponent).compute();
        GroupElement y = gpairing.pow(exponent).compute();

        return new VRFResult(y, pi);
    }

    public boolean isValid(GroupElement userPublicKeyG2, String context, VRFResult result) {
        Zn.ZnElement hashedContext = hashContext(context);

        // base = g2^m * PK_user = g2^(x + hashedContext)
        GroupElement baseG2 = g2.pow(hashedContext).op(userPublicKeyG2).compute();

        GroupElement zkp = result.getZeroKnowledgeProof();

        // Check if pairing holds: e(pi, g2^hashedContext * PK_user) == e(g1, g2)
        // e(g1^(1/(x+hashedContext)), g2^(x+hashedContext)) = e(g1, g2)^1
        GroupElement pairingCheck = map.apply(zkp, baseG2).compute();

        // Check if pseudorandom output token y matches e(pi, g2)
        GroupElement pairingToken = map.apply(zkp, g2).compute();
        
        return pairingCheck.equals(gpairing) && result.getPseudonym().equals(pairingToken);
    }
}
