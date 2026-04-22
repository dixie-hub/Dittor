package user;
/*Classe para os utilizadores que vão enviar um atributo para ser assinado pelas CAs e vao criar um pseudonimo para enviar para as DAs do Tor */

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import certificateauth.CA;

public class User {

    public String userID;

    public User() {
        userID = "user123"; //exemplo
    }

    public byte[] encryptData(X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;
        if (null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(userID.getBytes());
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                    .setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public byte[] sendAttribute() {
        try {
            InputStream certInput = getClass().getClassLoader().getResourceAsStream("certs/Baeldung.cer");

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInput);

            System.out.println("Original: " + new String(userID.getBytes()));
            byte[] attributeEncripted = encryptData(certificate);
            System.out.println("ID do user encriptado: " + Arrays.toString(attributeEncripted));

            byte[] result = CA.decryptData(attributeEncripted);

            return result;
        } catch (Exception e) {
            System.out.println("Failed to read certificate. Cause: " + e.getMessage());
        }
        return null;
    }
}
