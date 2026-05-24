import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import certificateauth.CA;
import directoryauth.DA;
import user.User;

public class Dittor {

    public static void main(String[] args) {
        System.out.println("Initializing Bilinear Group...");
        BilinearGroup pairing = new BarretoNaehrigBilinearGroup(100);
        Zn zp = pairing.getZn();

        //params for Pedersen Commitment
        GroupElement g = pairing.getG1().getGenerator();
        GroupElement h = pairing.getG1().getUniformlyRandomElement().compute();

        System.out.println("Running DKG protocol for CAs...");

        Zn.ZnElement a0 = zp.getUniformlyRandomElement(); //MASTER SECRET KEY
        Zn.ZnElement a1 = zp.getUniformlyRandomElement(); //polynomial coefficient

        GroupElement mpk = g.pow(a0).compute(); //Master Public Key = g ^ a0

        CA ca1 = new CA(1);
        ca1.setKeyShare(a0.add(a1.mul(zp.valueOf(1))), mpk);

        CA ca2 = new CA(2);
        ca2.setKeyShare(a0.add(a1.mul(zp.valueOf(2))), mpk);

        CA ca3 = new CA(3);
        ca3.setKeyShare(a0.add(a1.mul(zp.valueOf(3))), mpk);

        System.out.println("CAs with threshold keys!");

        User user = new User(pairing);

        System.out.println("User generating blinded commitment...");
        GroupElement commitment = user.createBlindedCommit(g, h);

        System.out.println("Sending commitment to CA 1 and CA 2");
        GroupElement share1 = ca1.issueSignatureShare(commitment);
        GroupElement share2 = ca2.issueSignatureShare(commitment);

        System.out.println("User aggregation shares...");
        GroupElement aggregatedBlindedSignature = user.aggregateShares(share1, share2);

        GroupElement expectedSignature = commitment.pow(a0).compute();

        if (aggregatedBlindedSignature.equals(expectedSignature))
            System.out.println("User successfully signed its attributes!");
        else
            System.out.println("This did not work correctly.");
    }

}
