package directoryauth;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/* Classe para as Directory Authorities do Tor

Responsaveis por:
- Validar pseudonimos que os utilizadores enviam
 */

public class DA {

        private static Store certs;
        private List<X509Certificate> certList;

        public DA() {
                certList = new ArrayList<X509Certificate>();
                try {
                        certs = new JcaCertStore(certList);
                } catch (CertificateEncodingException e) {
                        System.out.println("Certificates store failed to create. Cause: " + e.getMessage());
                }
        }

        public static boolean verifSignedData(byte[] signedData) throws Exception {

                X509Certificate signCert = null;
                ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
                ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
                CMSSignedData cmsSignedData = new CMSSignedData(
                                ContentInfo.getInstance(asnInputStream.readObject()));

                SignerInformationStore signers = ((CMSSignedData) cmsSignedData.getCertificates()).getSignerInfos();
                SignerInformation signer = signers.getSigners().iterator().next();
                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                X509CertificateHolder certHolder = certCollection.iterator().next();

                return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        }

}
