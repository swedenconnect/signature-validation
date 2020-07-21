package se.idsec.sigval.cert.utils;

import lombok.Data;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import se.idsec.sigval.cert.extensions.missing.SubjectInformationAccess;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.SubjectInfoAccessExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
public class CertUtils {

  private CertUtils() {
  }

  public static final String OCSP_NO_CHECK_EXT = "1.3.6.1.5.5.7.48.1.5";
  private static final String[] generalNameTagText = new String[] {
    "Other Name",
    "E-Mail",
    "DNS",
    "x400Address",
    "Directory Name",
    "EDI Party Name",
    "URI",
    "IP Address",
    "Registered ID" };


  public static String getOCSPUrl(X509Certificate certificate) throws IOException {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
    } catch (IOException ex) {
      log.warn("Failed to get OCSP URL" + ex.getMessage());
      return null;
    }

    if (obj == null) {
      log.debug("This certificate is not supported by OCSP checking");
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
      log.warn("Exception while accessing CRL Distribution point extension" + ex.getMessage());
      return null;
    }
    if (obj == null) {
      log.debug("This certificate is not supported by CRL checking");
      return null;
    }
    return CRLDistPoint.getInstance(obj);
  }

  public static SubjectInformationAccess getSIAExtension(X509Certificate certificate) {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, Extension.subjectInfoAccess.getId());
    } catch (IOException ex) {
      log.warn("Exception while accessing CRL Distribution point extension" + ex.getMessage());
      return null;
    }
    if (obj == null) {
      log.debug("This certificate is not supported by CRL checking");
      return null;
    }
    return SubjectInformationAccess.getInstance(obj);
  }

  public static boolean isOCSPNocheckExt(X509Certificate certificate) {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, OCSP_NO_CHECK_EXT);
    } catch (IOException ex) {
      log.warn("Exception while accessing OCSP-nocheck extension" + ex.getMessage());
      return false;
    }
    log.debug(obj != null ? "Target certificate has ocsp-nocheck" : "Target certificate does not have ocsp-nocheck");
    return obj != null;
  }

  /**
   * Verifies that a certificate currently is within its validity period
   * @param certificate certificate to check
   * @return true if the certificate is within its validity period
   */
  public static boolean isCurrentlyValid(X509Certificate certificate){
    return isCurrentlyValid(certificate, new Date());
  }

  /**
   * Verifies that a certificate at a specified time was within its validity period
   * @param certificate certificate to check
   * @param validationTime the time when the certificate should be valid
   * @return true if the certificate was within its validity period at the specified time
   */
  public static boolean isCurrentlyValid(X509Certificate certificate, Date validationTime){
    Date notBefore = certificate.getNotBefore();
    Date notAfter = certificate.getNotAfter();
    boolean notYetValid = validationTime.before(notBefore);
    boolean expired = validationTime.after(notAfter);
    if (notYetValid) {
      log.debug("Certificate not yet valid for {}", certificate.getSubjectX500Principal().toString());
    }
    if (expired) {
      log.debug("Certificate expired for {}", certificate.getSubjectX500Principal().toString());
    }
    return !notYetValid && !expired;
  }

  /**
   * Get a certificate from input stream
   * @param inStream input stream
   * @return certificate
   * @throws CertificateException error parsing certificate data
   * @throws IOException IO errors
   */
  public static X509Certificate getCert (InputStream inStream) throws CertificateException, IOException {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate)cf.generateCertificate(inStream);
    }
    finally {
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  private static String getGeneralNamesString(GeneralNames genNames) {
    GeneralName[] names = genNames.getNames();
    StringBuilder b = new StringBuilder();
    b.append("GeneralNames {");
    for (int i = 0; i < names.length; i++) {
      b.append(getGeneralNameStr(names[i]));
      if (i + 1 < names.length) {
        b.append(" | ");
      }
    }
    b.append("}");
    return b.toString();
  }

  public static String getGeneralNameStr(GeneralName generalName) {
    if (generalName == null) {
      return "null";
    }
    String toString = generalName.toString();
    try {
      int tagNo = Integer.valueOf(toString.substring(0, toString.indexOf(":")));
      return generalNameTagText[tagNo] + toString.substring(toString.indexOf(":"));

    }
    catch (Exception e) {
      return toString;
    }
  }

}
