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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class CA {

    private List<String> certifiedUsers;
    private static Store certs;
    private List<X509Certificate> certList;
    public static X509Certificate userCertificate;
    public static X509Certificate caCertificate;

    private static PrivateKey key;

    public CA() {
        certifiedUsers = new ArrayList<>();
        certList = new ArrayList<X509Certificate>();

        try {
            loadKeys();
            certs = new JcaCertStore(certList);
        } catch (Exception e) {
            System.out.println("Failed to load keys for the Certificate Authority. Cause: " + e.getMessage());
        }
    }

    private void loadKeys() throws CertificateException, NoSuchProviderException, IOException, KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());

        InputStream userCertInput = getClass().getClassLoader().getResourceAsStream("certs/user.cer");
        InputStream caCertInput = getClass().getClassLoader().getResourceAsStream("certs/ca.cer");

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        userCertificate = (X509Certificate) certFactory.generateCertificate(userCertInput);
        caCertificate = (X509Certificate) certFactory.generateCertificate(caCertInput);

        certList.add(userCertificate); // colocar todos os certificados available para a CA numa lista

        char[] keystorePassword = "password".toCharArray(); // so para motivos de emulacao
        char[] keyPassword = "password".toCharArray(); // so para motivos de emulacao

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream userKeyInput = getClass().getClassLoader().getResourceAsStream("certs/ca.p12");
        keystore.load(userKeyInput, keystorePassword);
        key = (PrivateKey) keystore.getKey("ca", keyPassword);
    }

    public byte[] decryptData(byte[] encryptedData)
            throws CMSException, IOException, OperatorCreationException, CertificateException {

        byte[] decryptedData = null;
        if (null != encryptedData) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(key);

            decryptedData = recipientInfo.getContent(recipient);

            String[] message = new String(decryptedData, StandardCharsets.UTF_8).split("\\|\\|");

            byte[] attributeBytes = Base64.getDecoder().decode(message[0]);
            byte[] signatureBytes = Base64.getDecoder().decode(message[1]);

            if (!verifSignedData(signatureBytes, attributeBytes)) {
                System.out.println("A mensagem foi intercetada ou a assinatura do utilizador não é válida.");
                return null;
            }

            String[] attributes = new String(attributeBytes, StandardCharsets.UTF_8).split("\\|\\|");

            String userID = attributes[0]; //TODO: transformar isto em Zero-Knowledge, transformando isto num hash
            Timestamp timeSent = Timestamp.valueOf(attributes[1]);
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());

            if (timeSent.after(currentTime)) {
                System.out.println("Mensagem inválida.");
                return null;
            }
            if (currentTime.getTime() - timeSent.getTime() > 30000) {
                System.out.println("Tentativa de replay de mensagem antiga.");
                return null;
            }

            if (certifiedUsers.contains(userID)) {
                System.out.println("Utilizador já tem um pseudónimo criado.");
                return null;
            }

            certifiedUsers.add(userID);
                
        }
        return decryptedData;
    }

    private static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey)
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

    public static boolean verifSignedData(byte[] signedData, byte[] attributeBytes)
            throws CMSException, IOException, OperatorCreationException, CertificateException { //TODO: verificar se a assinatura do user e valida, garantindo que o seu certificado e valido

        CMSSignedData cmsSignedData = new CMSSignedData(signedData);

        byte[] signedContent = (byte[]) cmsSignedData.getSignedContent().getContent();

        if (!Arrays.equals(signedContent, attributeBytes)) {
            return false;
        }

        /*
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(
                ContentInfo.getInstance(asnInputStream.readObject()));
        */

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        if (!cert.equals(userCertificate)) //certificado nao e o do user, mas nao verifica se e valido
            return false;

        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder));
    }

}
