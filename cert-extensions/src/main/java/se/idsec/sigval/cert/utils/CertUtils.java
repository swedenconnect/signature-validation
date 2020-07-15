package se.idsec.sigval.cert.utils;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Log
public class CertUtils {

  private CertUtils() {
  }

  public static final String OCSP_NO_CHECK_EXT = "1.3.6.1.5.5.7.48.1.5";

  public static String getOCSPUrl(X509Certificate certificate) throws IOException {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
    } catch (IOException ex) {
      log.warning("Failed to get OCSP URL" + ex.getMessage());
      return null;
    }

    if (obj == null) {
      log.fine("This certificate is not supported by OCSP checking");
      return null;
    }

    AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);
    Optional<String> ocspUrlOptional = Arrays.stream(authorityInformationAccess.getAccessDescriptions())
      .filter(accessDescription -> accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod))
      .filter(accessDescription -> accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier)
      .map(accessDescription -> DERIA5String.getInstance((ASN1TaggedObject) accessDescription.getAccessLocation().toASN1Primitive(), false)
        .getString())
      .findFirst();

    return ocspUrlOptional.isPresent() ? ocspUrlOptional.get() : null;
  }

  /**
   * @param certificate
   *            the certificate from which we need the ExtensionValue
   * @param oid
   *            the Object Identifier value for the extension.
   * @return the extension value as an ASN1Primitive object
   * @throws IOException
   */
  public static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
    byte[] bytes = certificate.getExtensionValue(oid);
    if (bytes == null) {
      return null;
    }
    ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
    ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
    aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
    return aIn.readObject();
  }

  public static List<X509Certificate> getCertificateList(X509CertificateHolder[] certificateHolders) throws CertificateException {
    if (certificateHolders == null || certificateHolders.length ==0){
      return new ArrayList<>();
    }
    List<X509Certificate> certList = new ArrayList<>();
    for (X509CertificateHolder certificateHolder : certificateHolders){
      certList.add(new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder));
    }
    return certList;
  }

  public static CRLDistPoint getCrlDistPoint(X509Certificate certificate) throws IOException {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, Extension.cRLDistributionPoints.getId());
    } catch (IOException ex) {
      log.warning("Exception while accessing CRL Distribution point extension" + ex.getMessage());
      return null;
    }
    if (obj == null) {
      log.fine("This certificate is not supported by CRL checking");
      return null;
    }
    return CRLDistPoint.getInstance(obj);
  }

  public static boolean isOCSPNocheckExt(X509Certificate certificate) {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, OCSP_NO_CHECK_EXT);
    } catch (IOException ex) {
      log.warning("Exception while accessing OCSP-nocheck extension" + ex.getMessage());
      return false;
    }
    log.fine(obj != null ? "Target certificate has ocsp-nocheck" : "Target certificate does not have ocsp-nocheck");
    return obj != null;
  }
}
