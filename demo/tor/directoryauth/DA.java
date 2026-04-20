/* Classe para as Directory Authorities do Tor

Responsaveis por:
- Validar pseudonimos que os utilizadores enviam
 */
public class DA {

    public DA() {

    }

    public static boolean verifSignedData(byte[] signedData)
            throws Exception {

        X509Certificate signCert = null;
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(
                ContentInfo.getInstance(asnInputStream.readObject()));

        SignerInformationStore signers = cmsSignedData.getCertificates().getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();

        return signer
                .verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .build(certHolder));
    }

}
