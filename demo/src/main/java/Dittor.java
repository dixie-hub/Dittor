import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import certificateauth.CA;
import directoryauth.DA;
import user.User;

public class Dittor {

    public static void main(String[] args) {
        User user = new User();
        CA ca = new CA();
        DA da = new DA();

        System.out.println("Successfully created all entities!");

        try {
            System.out.println("Sending user's attribute to the CA...");
            byte[] userRequest = user.sendAttribute();
            byte[] decryptedData = ca.receiveRequest(userRequest);

            BigInteger muPrime = new BigInteger(decryptedData);
            byte[] signature = user.receiveSignedAttribute(muPrime);

            System.out.println("Result: " + Base64.getEncoder().encodeToString(signature));
            if (decryptedData == null) {
                System.out.println("Failed to send user's attribute to the CA");
                return;
            }
        } catch (CMSException | OperatorCreationException | CertificateException | IOException
                | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            System.out.println("Something went wrong: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
