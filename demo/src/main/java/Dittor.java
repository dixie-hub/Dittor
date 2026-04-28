import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;

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
            byte[] userMessage = user.sendAttribute();
            byte[] decryptedData = ca.decryptData(userMessage);

            if (decryptedData == null) {
                System.out.println("Failed to send user's attribute to the CA");
                return;
            }
        } catch (CMSException e) {
            System.out.println("Something went wrong: " + e.getMessage());
        }
    }

}
