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

  /**
   * test if a CMS signature is a SVT document timestamp signature
   * @param sigBytes bytes of the CMS signature
   * @return true if this is a document timestamp signature containing an SVT
   */
  public static boolean isSVADocTimestamp(byte[] sigBytes) {
    try {
      TSTInfo tstInfo = getCmsSigTSTInfo(sigBytes);
      String svaJwt = getSVTJWT(tstInfo);
      SignedJWT parsedJWT = SignedJWT.parse(svaJwt);
      SVTClaims svaClaims = getSVTClaims(parsedJWT.getJWTClaimsSet());
      return true;
    }
    catch (Exception ex) {
      return false;
    }
  }

  /**
   * Get the SVT claims from a JWT claims set
   * @param jwtClaimsSet the source JWT claims set
   * @return SVT claims
   * @throws IOException on parsing errors
   */
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

  /**
   * Get the SVT JWT string from time stamp tstInfo
   * @param tstInfo timestamp data
   * @return SVT JWT (Json Web Token)
   * @throws IOException on parsing errors
   */
  public static String getSVTJWT(TSTInfo tstInfo) throws IOException {
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

  /**
   * Get timestamp TST ino from CMS signature bytes
   * @param sigBytes CMS signature bytes
   * @return TSTInfo from signature bytes
   * @throws IOException on parsing errors
   */
  public static TSTInfo getCmsSigTSTInfo(byte[] sigBytes) throws IOException {
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

  /**
   * Get the CMS SignedData object from a CMS signature
   * @param sigBytes CMS signature bytes
   * @return CMS SignedData object
   * @throws IOException on parsing errors
   */
  public static SignedData getSignedDataFromSignature(byte[] sigBytes) throws IOException {
    ContentInfo contentInfo = ContentInfo.getInstance(new ASN1InputStream(sigBytes).readObject());
    if (!contentInfo.getContentType().equals(PKCSObjectIdentifiers.signedData)) {
      throw new IOException("Illegal content for PDF signature. Must contain SignedData");
    }
    return SignedData.getInstance(contentInfo.getContent());
  }

  /**
   * Get a certificate from byte input
   * @param certBytes certificate bytes
   * @return certificate object
   * @throws CertificateException exception creating certificate
   * @throws IOException exception parsing data
   */
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

  /**
   * Get a certificate or null
   * @param bytes certificate bytes
   * @return a certificate object, or null if certificate creation failed
   */
  public static X509Certificate getCertOrNull(byte[] bytes) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
    }
    catch (Exception ex) {
      return null;
    }
  }

  /**
   * Get an ordered certificate list beginning with leaf cert and ending with parent trust anchor
   * @param signerCertificate target leaf certificate
   * @param certificateChain supporting certificate chain
   * @return ordered list of certificates beginning with target certificate
   */
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

  /**
   * Get the parent certificate
   * @param sigCert target certificate
   * @param chain supporting chain
   * @return parent certificate if present or null
   */
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
   * Verifies the SVT signature.
   *
   * @param signedJWT signed JWT holding the SVT
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
