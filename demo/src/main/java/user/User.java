package user;
/*Classe para os utilizadores que vão enviar um atributo para ser assinado pelas CAs e vao criar um pseudonimo para enviar para as DAs do Tor */

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
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
    public static RSAPublicKey caPublicKey;

    private byte[] userSecret;

    private BigInteger r;
    private BigInteger m;

    public User() {
        try {
            userSecret = new byte[32];
            new SecureRandom().nextBytes(userSecret);
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
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            String context = "TorRelay"; 

            byte[] userInput = ByteBuffer.allocate(userSecret.length + context.getBytes().length).put(userSecret)
                    .put(context.getBytes(StandardCharsets.UTF_8)).array();
            String pseudonym = Base64.getEncoder().encodeToString(digest.digest(userInput));

            Timestamp currentTime = new Timestamp(System.currentTimeMillis());
            String attribute = pseudonym + "||" + currentTime.toString();
            byte[] attributeBytes = attribute.getBytes(StandardCharsets.UTF_8);

            byte[] hash = MessageDigest.getInstance("SHA-256").digest(attributeBytes);

            BigInteger mu = calculateMu(hash);

            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);

            String authPayloadString = Base64.getEncoder().encodeToString(userCertificate.getEncoded()) + "||"
                    + Base64.getEncoder().encodeToString(nonce);
            byte[] authPayload = authPayloadString.getBytes(StandardCharsets.UTF_8);
            byte[] auth = signData(authPayload);

            String message = Base64.getEncoder().encodeToString(mu.toByteArray()) + "||"
                    + Base64.getEncoder().encodeToString(authPayload) + "||" + Base64.getEncoder().encodeToString(auth);

            byte[] encryptedMu = encryptData(caCertificate, message.getBytes());

            return encryptedMu;
        } catch (Exception e) {
            System.out.println("Failed to read certificate. Cause: " + e.getMessage());
        }
        return null;
    }

    public byte[] receiveSignedAttribute(BigInteger muprime) {
        String caSignature = signatureCalculation(muprime);
        boolean signatureValid = verifySignature(caSignature);

        if (!signatureValid) {
            System.out.println("A assinatura da CA foi tampered");
            return null;
        }

        System.out.println("A assinatura da CA foi concluída com êxito!");
        return caSignature.getBytes();
    }

    private static byte[] signData(byte[] data)
            throws Exception {

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(userCertificate);
        JcaCertStore certs = new JcaCertStore(certList);

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

        caPublicKey = (RSAPublicKey) caCertificate.getPublicKey();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream userKeyInput = getClass().getClassLoader().getResourceAsStream("certs/user.p12");
        keystore.load(userKeyInput, keystorePassword);
        key = (PrivateKey) keystore.getKey("user", keyPassword);
    }

    private BigInteger calculateMu(byte[] message) {

        try {

            m = new BigInteger(1, message);

            BigInteger e = caPublicKey.getPublicExponent();

            BigInteger N = caPublicKey.getModulus();

            // Generate a random number so that it belongs to Z*n and is >1 and therefore r
            // is invertible in Z*n
            SecureRandom random = new SecureRandom();

            byte[] randomBytes = new byte[10];

            BigInteger one = new BigInteger("1"); // make BigInteger object equal to 1, so we can compare it later with
                                                  // the r produced to verify r>1
            BigInteger gcd = null; // initialise variable gcd to null

            do {
                random.nextBytes(randomBytes); // generate random bytes using the SecureRandom function

                r = new BigInteger(randomBytes); // make a BigInteger object based on the generated random bytes
                                                 // representing the number r

                gcd = r.gcd(caPublicKey.getModulus()); // calculate the gcd for random number r and the modulus of the
                                                       // keypair

            } while (!gcd.equals(one) || r.compareTo(N) >= 0 || r.compareTo(one) <= 0); // repeat until getting an r
                                                                                        // that satisfies all the
                                                                                        // conditions and belongs to Z*n
                                                                                        // and >1

            // now that we got an r that satisfies the restrictions described we can proceed
            // with calculation of mu

            BigInteger mu = ((r.modPow(e, N)).multiply(m)).mod(N); // Bob computes mu = H(msg) * r^e mod N

            return mu;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Calculate signature over mu'
     * Bob receives the signature over the blinded message that he sent to Alice
     * and removes the blinding factor to compute the signature over his actual
     * message
     * 
     * @param muprime
     * @return signature
     */
    private String signatureCalculation(BigInteger muprime) {
        try {
            BigInteger N = caPublicKey.getModulus(); // get modulus of the key pair

            BigInteger s = r.modInverse(N).multiply(muprime).mod(N); // Bob computes sig = mu'*r^-1 mod N, inverse of r
                                                                     // mod N multiplied with muprime mod N, to remove
                                                                     // the blinding factor

            byte[] bytes = Base64.getEncoder().encode(s.toByteArray()); // encode with Base64 encoding to be able to
                                                                        // read all the symbols

            String signature = (new String(bytes)); // make a string based on the byte array representing the signature

            System.out.println("Signature produced with Blind RSA procedure for message (hashed with SHA1): "
                    + new String(m.toByteArray()) + " is: ");

            System.out.println(signature);

            return signature;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Checks if the signature received from Alice, is a valid signature for the
     * message given, this can be easily computed because(m^d)^e modN = m
     * 
     * @param signature
     */
    private boolean verifySignature(String signature) {
        try {
            byte[] bytes = signature.getBytes(); // create a byte array extracting the bytes from the signature

            byte[] decodedBytes = Base64.getDecoder().decode(bytes); // decode the bytes with Base64 decoding (remember
                                                                     // we encoded with base64 earlier)

            BigInteger sig = new BigInteger(decodedBytes); // create the BigInteger object based on the bytes of the
                                                           // signature

            BigInteger e = caPublicKey.getPublicExponent();// get the public exponent of Alice's key pair

            BigInteger N = caPublicKey.getModulus(); // get the modulus of Alice's key pair

            BigInteger signedMessageBigInt = sig.modPow(e, N); // calculate sig^e modN, if we get back the initial
                                                               // message that means that the signature is valid, this
                                                               // works because (m^d)^e modN = m

            return signedMessageBigInt.equals(m);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
