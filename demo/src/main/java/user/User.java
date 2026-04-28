package user;
/*Classe para os utilizadores que vão enviar um atributo para ser assinado pelas CAs e vao criar um pseudonimo para enviar para as DAs do Tor */

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class User {

    public String userID;
    private static PrivateKey key;
    public static X509Certificate userCertificate;
    public static X509Certificate caCertificate;

    public User() {
        userID = "user123"; // exemplo

        try {
            loadKeys();
        } catch (Exception e) {
            System.out.println("Failed to load keys for the user. Cause: " + e.getMessage());
        }
    }

    public static byte[] encryptData(X509Certificate encryptionCertificate, byte[] hashedMessage)
            throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;
        if (null != encryptionCertificate && null != hashedMessage) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(hashedMessage);
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
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());
            String attribute = userID + "||" + currentTime.toString();
            byte[] attributeBytes = attribute.getBytes(StandardCharsets.UTF_8);

            byte[] signedData = signData(attributeBytes);

            String message = Base64.getEncoder().encodeToString(attributeBytes) + "||"
                    + Base64.getEncoder().encodeToString(signedData);

            byte[] messageEncrypted = encryptData(caCertificate, message.getBytes());

            return messageEncrypted;
        } catch (Exception e) {
            System.out.println("Failed to read certificate. Cause: " + e.getMessage());
        }
        return null;
    }

    private static byte[] signData(byte[] data)
            throws Exception {

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(userCertificate);
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(key);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                        .build())
                .build(contentSigner, userCertificate));
        cmsGenerator.addCertificates(certs);

        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        return cms.getEncoded();
    }

    private void loadKeys() throws CertificateException, NoSuchProviderException, IOException, KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());

        InputStream userCertInput = getClass().getClassLoader().getResourceAsStream("certs/user.cer");
        InputStream caCertInput = getClass().getClassLoader().getResourceAsStream("certs/ca.cer");

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        userCertificate = (X509Certificate) certFactory.generateCertificate(userCertInput);
        caCertificate = (X509Certificate) certFactory.generateCertificate(caCertInput);

        char[] keystorePassword = "password".toCharArray(); // so para motivos de emulacao
        char[] keyPassword = "password".toCharArray(); // so para motivos de emulacao

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream userKeyInput = getClass().getClassLoader().getResourceAsStream("certs/user.p12");
        keystore.load(userKeyInput, keystorePassword);
        key = (PrivateKey) keystore.getKey("user", keyPassword);
    }
}
