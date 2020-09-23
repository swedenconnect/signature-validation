package se.idsec.sigval.commons.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Base64;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.CertReferenceClaims;
import se.idsec.sigval.svt.claims.SVTClaims;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility methods for SVT processing
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SVAUtils {

  public static boolean isSVADocTimestamp(byte[] sigBytes) {
    try {
      TSTInfo tstInfo = getPdfDocTSTInfo(sigBytes);
      String svaJwt = getSVAJWT(tstInfo);
      SignedJWT parsedJWT = SignedJWT.parse(svaJwt);
      SVTClaims svaClaims = getSVTClaims(parsedJWT.getJWTClaimsSet());
      return true;
    }
    catch (Exception ex) {
      return false;
    }
  }

  public static SVTClaims getSVTClaims(JWTClaimsSet jwtClaimsSet) throws IOException {
    try {
      String svaClaimsJson = jwtClaimsSet.getClaim("sig_val_claims").toString();
      ObjectMapper mapper = new ObjectMapper();
      SVTClaims svaClaims = mapper.readValue(svaClaimsJson, SVTClaims.class);
      return svaClaims;
    }
    catch (Exception ex) {
      throw new IOException("No SVA claims available");
    }
  }

  public static String getSVAJWT(TSTInfo tstInfo) throws IOException {
    try {
      Extensions extensions = tstInfo.getExtensions();
      Extension svaExt = extensions.getExtension(new ASN1ObjectIdentifier("1.2.752.201.5.2"));
      String svaJwt = new String(svaExt.getExtnValue().getOctets(), StandardCharsets.UTF_8);
      return svaJwt;
    }
    catch (Exception ex) {
      throw new IOException("No SVA JWT is available in TSTInfo");
    }

  }

  public static TSTInfo getPdfDocTSTInfo(byte[] sigBytes) throws IOException {
    try {
      SignedData signedData = getSignedDataFromSignature(sigBytes);
      ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();
      if (!contentType.equals(PKCSObjectIdentifiers.id_ct_TSTInfo)) {
        throw new IOException("No timestamp available");
      }
      byte[] tstInfoBytes = ASN1OctetString.getInstance(signedData.getEncapContentInfo().getContent()).getOctets();
      return TSTInfo.getInstance(new ASN1InputStream(tstInfoBytes).readObject());
    }
    catch (Exception ex) {
      throw new IOException("Unable to parse TSTInfo data");
    }
  }

  public static SignedData getSignedDataFromSignature(byte[] sigBytes) throws IOException {
    ContentInfo contentInfo = ContentInfo.getInstance(new ASN1InputStream(sigBytes).readObject());
    if (!contentInfo.getContentType().equals(PKCSObjectIdentifiers.signedData)) {
      throw new IOException("Illegal content for PDF signature. Must contain SignedData");
    }
    return SignedData.getInstance(contentInfo.getContent());
  }

  /**
   * Gets the referenced certificate and certificate chain validated through a SVA {@link CertReferenceClaims} claim
   *
   * @param certRef                  claims used to retrieve or authenticate certificates
   * @param signatureCertificateList List of certificate candidates that should match certificate reference data
   * @param resultChain              An empty list where a resulting certificate chain will be stored
   * @param messageDigest            message digest instance
   * @return the identified signing certificate
   */
  public static X509Certificate getSVAReferencedCertificates(
    CertReferenceClaims certRef, List<byte[]> signatureCertificateList,
    List<X509Certificate> resultChain, MessageDigest messageDigest) throws IllegalArgumentException {

    try {
      String type = certRef.getType();
      CertReferenceClaims.CertRefType certRefType = CertReferenceClaims.CertRefType.valueOf(type.toLowerCase());
      switch (certRefType) {
      case chain:
        return getEmbeddedChain(certRef, resultChain);
      case chain_hash:
        return getReferencedChain(certRef, signatureCertificateList, resultChain, messageDigest);
      }
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Unable to parse SVA certificate reference: " + ex.getMessage());
    }
    throw new IllegalArgumentException("Unable to find a certificate that match the SVA certificate reference");
  }

  private static X509Certificate getReferencedChain(CertReferenceClaims certRef, List<byte[]> signatureCertificateList,
    List<X509Certificate> resultChain, MessageDigest messageDigest) throws Exception {
    List<String> certRefList = certRef.getRef();
    if (certRefList == null || certRefList.size() < 1 || certRefList.size() > 2) {
      throw new IllegalArgumentException("Cert and chain SVA certificate reference must contain 1 or 2 parameters in reference");
    }
    String certHashRef = certRefList.get(0);
    X509Certificate cert;
    Optional<X509Certificate> certOptional = findMatchingCert(signatureCertificateList, certHashRef, messageDigest);

    if (!certOptional.isPresent()) {
      throw new IllegalArgumentException("The referenced certificate does not match provided certificates");
    }
    cert = certOptional.get();

    if (certRefList.size() == 1) {
      // We are done. No chain hash was provided
      resultChain.add(cert);
      return cert;
    }

    String chainHashRef = certRefList.get(1);
    for (byte[] certBytes : signatureCertificateList) {
      messageDigest.update(certBytes);
    }
    String chainHash = Base64.toBase64String(messageDigest.digest());
    if (!chainHash.equals(chainHashRef)) {
      throw new IllegalArgumentException("The referenced certificate chain does not match provided certificates");
    }
    for (byte[] certBytes : signatureCertificateList) {
      X509Certificate certOrNull = getCertOrNull(certBytes);
      if (certOrNull != null) {
        resultChain.add(certOrNull);
      }
    }
    return cert;
  }

  private static X509Certificate getEmbeddedChain(CertReferenceClaims certRef, List<X509Certificate> resultChain)
    throws CertificateException, IOException {
    List<String> certRefList = certRef.getRef();
    X509Certificate cert = null;
    for (int i = 0; i < certRefList.size(); i++) {
      X509Certificate chainCert = getCertificate(Base64.decode(certRefList.get(i)));
      resultChain.add(chainCert);
      if (i == 0) {
        cert = chainCert;
      }
    }
    if (cert != null) {
      return cert;
    }
    throw new IllegalArgumentException("No valid certificate available in referenced SVA certificate");
  }

  private static Optional<X509Certificate> findMatchingCert(List<byte[]> signatureCertificateList, String certHashRef,
    MessageDigest messageDigest) {
    return signatureCertificateList.stream()
      .filter(bytes -> Base64.toBase64String(messageDigest.digest(bytes)).equals(certHashRef))
      .map(bytes -> getCertOrNull(bytes))
      .filter(x509Certificate -> x509Certificate != null)
      .findFirst();
  }

  public static X509Certificate getCertificate(byte[] certBytes) throws CertificateException, IOException {
    InputStream inStream = null;
    try {
      inStream = new ByteArrayInputStream(certBytes);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    } finally {
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  public static X509Certificate getCertOrNull(byte[] bytes) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
    }
    catch (Exception ex) {
      return null;
    }
  }

  public static List<X509Certificate> getOrderedCertList(byte[] signerCertificate, List<byte[]> certificateChain) {

    if (signerCertificate == null){
      return null;
    }

    if (certificateChain == null || certificateChain.size()<2){
      return Arrays.asList(getCertOrNull(signerCertificate));
    }

    List<X509Certificate> orderedList = new ArrayList<>();
    try {
      List<X509Certificate> chain = certificateChain.stream()
        .map(bytes -> getCertOrNull(bytes))
        .filter(x509Certificate -> x509Certificate != null)
        .collect(Collectors.toList());
      X509Certificate sigCert = getCertificate(signerCertificate);
      orderedList.add(sigCert);
      boolean more = true;
      while (more){
        X509Certificate parentCert = getParentCert(sigCert, chain);
        if (parentCert != null) {
          orderedList.add(parentCert);
          try {
            // Slef issued. End here
            parentCert.verify(parentCert.getPublicKey());
            more = false;
          } catch (Exception ex){
            // Not self issued. Continue
            sigCert = parentCert;
          }
        } else {
          more = false;
        }
      }
      return orderedList;
    } catch (Exception ex) {
      return null;
    }
  }

  private static X509Certificate getParentCert(X509Certificate sigCert, List<X509Certificate> chain) {
    for (X509Certificate certFromChain: chain){
      try {
        sigCert.verify(certFromChain.getPublicKey());
        return certFromChain;
      } catch (Exception ex){
        continue;
      }
    }
    return null;
  }

  /**
   * Verifies the SVA.
   *
   * @param publicKey the public key used to verify the SVA token signature
   * @throws Exception if validation of SVA fails
   */
  public static void verifySVA(SignedJWT signedJWT, PublicKey publicKey) throws Exception {
    //Check for expiry
    Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
    if (expirationTime != null) {
      if (new Date().after(expirationTime)) {
        throw new RuntimeException("The SVA has expired");
      }
    }

    JWSVerifier verifier = publicKey instanceof RSAPublicKey ?
      new RSASSAVerifier((RSAPublicKey) publicKey) :
      new ECDSAVerifier((ECPublicKey) publicKey);

    //Verify that the hash algorithm is consistent with the SVA claims
    JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
    SVTAlgoRegistry.AlgoProperties algoParams = SVTAlgoRegistry.getAlgoParams(algorithm);

    DigestAlgorithm svaSigHashAlgo = DigestAlgorithmRegistry.get(algoParams.getDigestAlgoId());
    SVTClaims svtClaims = getSVTClaims(signedJWT.getJWTClaimsSet());
    DigestAlgorithm svaClaimsHashAlgo = DigestAlgorithmRegistry.get(svtClaims.getHash_algo());
    if (!svaSigHashAlgo.equals(svaClaimsHashAlgo)) {
      throw new IOException(
        "SVA hahs algo mismatch. SVA algo: " + svaClaimsHashAlgo.getUri() + ", SVA token sig algo: " + svaSigHashAlgo.getUri());
    }
    signedJWT.verify(verifier);
  }

  public static SignedJWT getMostRecentJwt(List<SignedJWT> signedJWTList){
    if (signedJWTList == null || signedJWTList.isEmpty()){
      return null;
    }

    Optional<SignedJWT> signedJWTOptional = signedJWTList.stream()
      .sorted((o1, o2) -> compareSVTIssueDate(o1, o2))
      .findFirst();

    return signedJWTOptional.isPresent() ? signedJWTOptional.get() : null;
  }

  /**
   * Compare jwt issue date to support sorting to place the most recent item first in the list
   * @param o1 Signed JWT*
   * @param o2 Other Signed JWT
   * @return negative if first date is after (more recent) than second date
   */
  public static int compareSVTIssueDate(SignedJWT o1, SignedJWT o2) {
    Date date1 = getSVTIssueDate(o1);
    Date date2 = getSVTIssueDate(o2);
    return date1.after(date2) ? -1 : 1;
  }

  /**
   * Obtains the date from SVT JWT
   * @param o1 SignedJWT
   * @return the issue date or epoc time if date is not set.
   */
  public static Date getSVTIssueDate(SignedJWT o1) {
    try {
      return o1.getJWTClaimsSet().getIssueTime();
    } catch (Exception ex){
      log.error("Error reading issue time from SVT JWT - {}", ex.getMessage());
      // Date is missing. Return epoc time
      return new Date(0);
    }
  }


}
