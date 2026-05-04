import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
            byte[] decryptedData = ca.decryptData(userRequest);
            System.out.println("Result: " + Base64.getDecoder().decode(decryptedData));
            if (decryptedData == null) {
                System.out.println("Failed to send user's attribute to the CA");
                return;
            }
        } catch (CMSException | OperatorCreationException | CertificateException | IOException e) {
            System.out.println("Something went wrong: " + e.getMessage());
        }
    }

}
