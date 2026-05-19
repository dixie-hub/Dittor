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

import java.io.IOException;
import java.io.InputStream;

import java.math.BigInteger;

import java.nio.charset.StandardCharsets;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class CA {

    private Set<String> usedNonces;
    private Set<String> certifiedUsers;
    private List<X509Certificate> certList;

    public X509Certificate userCertificate;
    public X509Certificate caCertificate;

    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey publicKey;

    public CA() {
        usedNonces = new HashSet<>(); //bloom filter?
        certList = new ArrayList<X509Certificate>();
        certifiedUsers = new HashSet<>();

        try {
            loadKeys();
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

        publicKey = (RSAPublicKey) caCertificate.getPublicKey();

        certList.add(userCertificate); // colocar todos os certificados available para a CA numa lista

        char[] keystorePassword = "password".toCharArray(); // so para motivos de emulacao
        char[] keyPassword = "password".toCharArray(); // so para motivos de emulacao

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream userKeyInput = getClass().getClassLoader().getResourceAsStream("certs/ca.p12");
        keystore.load(userKeyInput, keystorePassword);

        Enumeration<String> aliases = keystore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            Key key = keystore.getKey(alias, keyPassword);
            if (key instanceof RSAPrivateCrtKey) {
                privateKey = (RSAPrivateCrtKey) key;
                break;
            }
        }

        if (privateKey == null)
            throw new RuntimeException("CA private key not found in keystore");

    }

    public byte[] receiveRequest(byte[] encryptedData)
            throws CMSException, IOException, OperatorCreationException, CertificateException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

        byte[] decryptedData = null;
        if (null != encryptedData) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

            decryptedData = recipientInfo.getContent(recipient);

            String[] message = new String(decryptedData, StandardCharsets.UTF_8).split("\\|\\|");

            BigInteger mu = new BigInteger(1, Base64.getDecoder().decode(message[0]));
            byte[] authPayload = Base64.getDecoder().decode(message[1]);
            byte[] signatureBytes = Base64.getDecoder().decode(message[2]);

            if (!verifSignedData(signatureBytes, authPayload)) {
                System.out.println("A mensagem foi intercetada ou a assinatura do utilizador não é válida.");
                return null;
            }
            if (!verifAuthPayload(authPayload)) {
                System.out.println("A mensagem não é válida.");
                return null;
            }

            BigInteger muPrime = calculateMuPrimeWithChineseRemainderTheorem(mu);

            return muPrime.toByteArray();
        }
        return decryptedData;
    }

    /*
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
    */

    public boolean verifSignedData(byte[] signedData, byte[] authPayload)
            throws CMSException, IOException, OperatorCreationException, CertificateException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        CMSSignedData cmsSignedData = new CMSSignedData(signedData);

        byte[] signedContent = (byte[]) cmsSignedData.getSignedContent().getContent();


        /* if (!Arrays.equals(signedContent, authPayload)) {
            return false;
        } */

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        cert.checkValidity();
        cert.verify(caCertificate.getPublicKey());

        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder));
    }

    private boolean verifAuthPayload(byte[] authPayload) throws NoSuchAlgorithmException {
        String[] authFields = new String(authPayload, StandardCharsets.UTF_8).split("\\|\\|");

        byte[] certBytes = Base64.getDecoder().decode(authFields[0]);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        String userFingerprint = Base64.getEncoder().encodeToString(digest.digest(certBytes));

        byte[] nonce = Base64.getDecoder().decode(authFields[1]);

        String nonceString = Base64.getEncoder().encodeToString(nonce);
        if (usedNonces.contains(nonceString) || certifiedUsers.contains(userFingerprint)) {
            System.out.println("User already received a credential");
            return false;
        }

        usedNonces.add(nonceString);
        certifiedUsers.add(userFingerprint);

        return true;
    }

    /**
     * Calculate mu' using the Chinese Remainder Theorem for optimization
     * Thanks to the isomorphism property f(x+y)=f(x)+f(y) we can split the mu^d
     * modN in two:
     * one mode p , one mode q, and then we can combine the results to calculate
     * muprime
     * 
     * @param mu
     * @return mu'
     */
    private BigInteger calculateMuPrimeWithChineseRemainderTheorem(BigInteger mu) {
        try {
            BigInteger N = publicKey.getModulus(); // get modulus N

            BigInteger P = privateKey.getPrimeP(); // get the prime number p used to produce the key pair

            BigInteger Q = privateKey.getPrimeQ(); // get the prime number q used to produce the key pair

            // We split the mu^d modN in two , one mode p , one mode q

            BigInteger PinverseModQ = P.modInverse(Q); // calculate p inverse modulo q

            BigInteger QinverseModP = Q.modInverse(P); // calculate q inverse modulo p

            BigInteger d = privateKey.getPrivateExponent(); // get private exponent d

            // We split the message mu in to messages m1, m2 one mod p, one mod q

            BigInteger dP = d.mod(P.subtract(BigInteger.ONE));
            BigInteger dQ = d.mod(Q.subtract(BigInteger.ONE));

            BigInteger m1 = mu.modPow(dP, P); // calculate m1=(mu^d modN)modP

            BigInteger m2 = mu.modPow(dQ, Q); // calculate m2=(mu^d modN)modQ

            // We combine the calculated m1 and m2 in order to calculate muprime
            // We calculate muprime: (m1*Q*QinverseModP + m2*P*PinverseModQ) mod N where N
            // =P*Q

            BigInteger muprime = ((m1.multiply(Q).multiply(QinverseModP)).add(m2.multiply(P).multiply(PinverseModQ)))
                    .mod(N);

            return muprime;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
