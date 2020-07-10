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

/*
    AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
    for (AccessDescription accessDescription : accessDescriptions) {
      boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
      if (!correctAccessMethod) {
        continue;
      }

      GeneralName name = accessDescription.getAccessLocation();
      if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
        continue;
      }

      DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
      return derStr.getString();
    }

    return null;
*/

  }

  /**
   * @param certificate
   *            the certificate from which we need the ExtensionValue
   * @param oid
   *            the Object Identifier value for the extension.
   * @return the extension value as an ASN1Primitive object
   * @throws IOException
   */
  private static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
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

}
