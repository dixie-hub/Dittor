import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import certificateauth.CA;
import directoryauth.DA;
import user.User;

public class Dittor {

    public static void main(String[] args) {
        User user = new User();
        CA ca = new CA();
        DA da = new DA();

        System.out.println("Successfully created all entities!");

        System.out.println("Sending user's attribute to the CA...");
        byte[] result = user.sendAttribute();
        if (result == null) {
            System.out.println("Failed to send user's attribute to the CA");
            return;
        }
    }

}
