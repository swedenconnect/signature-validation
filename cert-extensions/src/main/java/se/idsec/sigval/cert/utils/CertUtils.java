/*
 * Copyright (c) 2020. IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.idsec.sigval.cert.utils;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import se.idsec.sigval.cert.enums.OidName;
import se.idsec.sigval.cert.extensions.missing.SubjectInformationAccess;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility class for X.509 Certificate related functions
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CertUtils {

  /**
   * Private constructor to prevent instantiation
   */
  private CertUtils() {
  }

  /** General name display names */
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

  /**
   * Get OCSP url from certificate
   * @param certificate certificate
   * @return OCSP responder URL or null if no such URL is present
   */
  public static String getOCSPUrl(X509Certificate certificate) {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
    } catch (IOException ex) {
      log.warn("Failed to get OCSP URL" + ex.getMessage());
      return null;
    }

    if (obj == null) {
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
   * @throws IOException on error
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

  /**
   * Get CRL Distribution point extension from certificate
   * @param certificate certificate
   * @return {@link CRLDistPoint} extension or null if no such extension is present
   * @throws IOException on error obtaining extension data
   */
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

  /**
   * Get Subject information access extension from certificate
   * @param certificate certificate
   * @return {@link SubjectInformationAccess}
   */
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

  /**
   * Test if certificate has OCSP no-check extension
   * @param certificate certificate
   * @return true if OCSP no-check extension is present
   */
  public static boolean isOCSPNocheckExt(X509Certificate certificate) {
    ASN1Primitive obj;
    try {
      obj = getExtensionValue(certificate, OidName.id_pkix_ocsp_nocheck.getOid());
    } catch (IOException ex) {
      log.warn("Exception while accessing OCSP-nocheck extension" + ex.getMessage());
      return false;
    }
    log.trace(obj != null ? "Target certificate has ocsp-nocheck" : "Target certificate does not have ocsp-nocheck");
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

  /**
   * Get the presentation name string of general names
   * @param genNames X.509 certificate general names
   * @return presentation string
   */
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

  /**
   * Get the general name string for a particular general name
   * @param generalName general name
   * @return presentation string
   */
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

  /**
   * This method returns the resulting path as a list of certificates starting from the target certificate, ending in the trust anchor certificate
   * @param result validated certificate path
   * @return validated certificate path starting with the target certificate and ending with the self signed TA root certificate
   */
  public static List<X509Certificate> getResultPath(PKIXCertPathBuilderResult result){
    try {
      List<X509Certificate> x509CertificateList = result.getCertPath().getCertificates().stream()
        .map(certificate -> (X509Certificate) certificate)
        .collect(Collectors.toList());
      List<X509Certificate> resultPath = new ArrayList<>(x509CertificateList);
      // Add TA certificate
      resultPath.add(result.getTrustAnchor().getTrustedCert());
      return resultPath;
    } catch (Exception ex){
      throw new RuntimeException(ex.getMessage());
    }
  }


}
