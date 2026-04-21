import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
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

        System.out.println("Sending user's id to CA...");
        try {
            File certFile = new File("demo\\src\\main\\java\\certs\\Baeldung.cer");
            DataInputStream reader = new DataInputStream(new FileInputStream(certFile));
            int nBytesToRead = reader.available();
            if (nBytesToRead > 0) {
                byte[] bytes = new byte[nBytesToRead];
                reader.read(bytes);
            }

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(reader);
            reader.close();

            user.encryptData(certificate);
        } catch (Exception e) {
            System.out.println("Failed to read certificate. Cause: " + e.getMessage());
        }
    }

}
