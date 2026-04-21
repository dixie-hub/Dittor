package certificateauth;
/*Classe para as Certificate Authorities que vão comunicar entre si para produzirem uma assinatura por cima de um atributo de um user 

Responsabilidades:
- Emitir credenciais (assinaturas por cima dos atributos)
- Garantir unicidade de users (ser sybil-resistant)
- Guardar memória dos users
- Threshold issuance?

Setup:
- gera(chavepriv, chavepub), para comunicar com outras CAs e com os users
- envia chavepub para todos (Diffie-Hellman?)



*/

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CA {

    private List<UUID> certifiedUsers;
    private static PrivateKey key;

    public CA() {
        certifiedUsers = new ArrayList<>();

        try {
            loadKeys();
        } catch (Exception e) {
            System.out.println("Failed to load keys for the Certificate Authority. Cause: " + e.getMessage());
        }
    }

    private void loadKeys() throws CertificateException, NoSuchProviderException, IOException, KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");

        InputStream certInput = getClass().getClassLoader().getResourceAsStream("certs/Baeldung.cer");
        if (certInput == null) {
            throw new RuntimeException("O certificado não foi encontrado na pasta dos resources");
        }

        certFactory.generateCertificate(certInput);

        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        certInput = getClass().getClassLoader().getResourceAsStream("certs/Baeldung.p12");
        keystore.load(certInput, keystorePassword);
        key = (PrivateKey) keystore.getKey("baeldung", keyPassword);
    }

    public static byte[] decryptData(byte[] encryptedData) throws CMSException {

        byte[] decryptedData = null;
        if (null != encryptedData) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(key);

            return recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    public static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey)
            throws Exception {

        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                        .build())
                .build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);

        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

}
