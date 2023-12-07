/*
 * Copyright (c) 2020-2022.  Sweden Connect
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

package se.swedenconnect.sigval.jose.svt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.sigval.svt.algorithms.SVTAlgoRegistry;
import se.swedenconnect.sigval.svt.claims.SVTClaims;
import se.swedenconnect.sigval.svt.claims.SigReferenceClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;
import se.swedenconnect.sigval.svt.claims.SignedDataClaims;
import se.swedenconnect.sigval.svt.validation.SVTValidator;
import se.swedenconnect.sigval.svt.validation.SignatureSVTData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implements a validator for SVT tokens on JWS signatures
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class JOSESVTValidator extends SVTValidator<JOSESVTValInput> {
  /** Certificate chain validator for SVA tokens **/
  private final CertificateValidator svtCertVerifier;

  /**
   * Supporting certificates used to verify the signature on the SVT. A key ID is valid ref if it matches one of the certificates in this list.
   * If this list is empty, all necessary certificates for verifying the SVT must be present in the header of the SVT.
   */
  private final List<X509Certificate> supportingCertificates;

  /**
   * Constructor without any supporting validation certificates
   * @param svtCertVerifier certificate verifier used to verify the SVT signing certificate
   */
  public JOSESVTValidator(CertificateValidator svtCertVerifier) {
    this.svtCertVerifier = svtCertVerifier;
    this.supportingCertificates = new ArrayList<>();
  }

  /**
   * Constructor that allows passing of supporting certificates
   * @param svtCertVerifier certificate verifier used to verify the SVT signing certificate
   * @param supportingCertificates supporting certificates used to verify the SVT signature
   */
  public JOSESVTValidator(CertificateValidator svtCertVerifier, List<X509Certificate> supportingCertificates) {
    this.svtCertVerifier = svtCertVerifier;
    this.supportingCertificates = supportingCertificates != null ? supportingCertificates : new ArrayList<>();
  }

  /**
   * Extract relevant data from the JWS signature necessary to validate its consistency with an SVT record.
   *
   * @return a list of {@link SignatureSVTData} object. This list is either empty or contains exactly 1 item.
   * @throws Exception if the process throws an exception
   */
  @Override protected List<SignatureSVTData> getSignatureSVTData(JOSESVTValInput signedDataInput) throws Exception {

    /**
     *     First locate the SVT tokens in this signature
     *     Validate them all
     *     Find the most recent one
     *
     *     Check that this signature match the SVT token
     *     Then gather data about this signature
     */

    List<String> svaTokenList = getSignatureSvaTokens(signedDataInput.getSignatureData().getUnprotectedHeader());
    List<SignedJWT>  signedJWTList = new ArrayList<>();
    for (String jwt: svaTokenList){
      try {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        verifyJWT(signedJWT);
        signedJWTList.add(signedJWT);
      } catch (Exception ex){
        log.debug("Failed to parse and validate SVT {}", ex.getMessage());
      }
    }
    // find most recent valid SVT
    SignedJWT mostRecentJwt = SVAUtils.getMostRecentJwt(signedJWTList);

    SignatureSVTData signatureSVTData = collectSignatureSVTData(signedDataInput, mostRecentJwt);
    return Arrays.asList(signatureSVTData);
  }

  /**
   * Collects the data from XML signature to compare with SVT token data to validate the signature through the SVT
   * @param signedDataInput signature validation input for XML signatures
   * @param mostRecentJwt the most recent SVT JWT
   * @return Signature SVT data
   * @throws Exception on any critical errors
   */
  private SignatureSVTData collectSignatureSVTData(JOSESVTValInput signedDataInput, SignedJWT mostRecentJwt) throws Exception {
    SignatureSVTData.SignatureSVTDataBuilder svtDataBuilder = SignatureSVTData.builder();
    SVTClaims svtClaims = SVAUtils.getSVTClaims(mostRecentJwt.getJWTClaimsSet());
    DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(svtClaims.getHash_algo());
    JOSESignatureData signatureData = signedDataInput.getSignatureData();

    // Set SVT JWT
    svtDataBuilder.signedJWT(mostRecentJwt);

    // Set signature ref
    final String tbsString = signatureData.getHeader().toBase64URL().toString() + "." + signatureData.getPayload().toBase64URL().toString();
    byte[] signedBytes = tbsString.getBytes(StandardCharsets.UTF_8);
    String signatureHash = toBase64Digest(signatureData.getSignatureBytes(), digestAlgorithm);
    String signedInfoHash = toBase64Digest(signedBytes, digestAlgorithm);
    svtDataBuilder.signatureReference(SigReferenceClaims.builder()
      .sig_hash(signatureHash)
      .sb_hash(signedInfoHash)
      .build());

    // Check signature match
    List<SignatureClaims> sigClaims = svtClaims.getSig();
    Optional<SignatureClaims> sigSVTClaimsOptional = sigClaims.stream()
      .filter(claims -> claims.getSig_ref().getSig_hash().equals(signatureHash))
      .findFirst();

    if (!sigSVTClaimsOptional.isPresent()) {
      //There is not SVT record that matches this signature. Skip signature.
      throw new RuntimeException("The validated SVT claims does not match the present signature");
    }
    svtDataBuilder.signatureClaims(sigSVTClaimsOptional.get());

    // Set signed data refs
    List<SignedDataClaims> signedDataClaimsList = new ArrayList<>();
    final SignedDataClaims signedDataClaims = SignedDataClaims.builder()
      .ref(signatureData.isDetached() ? "detached" : "payload")
      .hash(toBase64Digest(signatureData.getPayload().toBytes(), digestAlgorithm))
      .build();
    signedDataClaimsList = List.of(signedDataClaims);
    svtDataBuilder.signedDataRefList(signedDataClaimsList);

    final Iterator<X509Certificate> iterator = signatureData.getSignatureCertChain().iterator();
    List<byte[]> certList = new ArrayList<>();
    while (iterator.hasNext()) {
      certList.add(iterator.next().getEncoded());
    }
    svtDataBuilder.signerCertChain(certList);

    return svtDataBuilder.build();
  }

  private String toBase64Digest(byte[] bytes, DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
    return org.bouncycastle.util.encoders.Base64.toBase64String(
      digestAlgorithm.getInstance().digest(bytes));
  }

  private void verifyJWT(SignedJWT signedJWT) throws Exception {
    JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
    String keyID = signedJWT.getHeader().getKeyID();
    List<X509Certificate> jwtCertList = getJWTCerts(signedJWT.getHeader().getX509CertChain());
    JWTCerts jwtCerts = getAllJwtCerts (algorithm, keyID, jwtCertList);
    if (jwtCerts.getSigningCert() == null) throw new IOException("Unable to locate a SVT signing certificate");
    svtCertVerifier.validate(jwtCerts.getSigningCert(), jwtCerts.getSupportingCertList(), null);
    SVAUtils.verifySVA(signedJWT, jwtCerts.signingCert.getPublicKey());
  }

  private JWTCerts getAllJwtCerts(JWSAlgorithm algorithm, String keyID, List<X509Certificate> jwtCertList) throws Exception {
    X509Certificate signerCert = null;
    if (StringUtils.isNotEmpty(keyID)){
      Optional<X509Certificate> signCertOptional = supportingCertificates.stream()
        .filter(cert -> certMatchKeyId(cert, keyID, algorithm))
        .findFirst();
      if (signCertOptional.isPresent()) {
        signerCert = signCertOptional.get();
      } else {
        signCertOptional = jwtCertList.stream()
          .filter(cert -> certMatchKeyId(cert, keyID, algorithm))
          .findFirst();
        signerCert = signCertOptional.isPresent() ? signCertOptional.get() : null;
      }
      // We had a KeyID but no supporting certs matched this KeyID. Return null
      if (signerCert == null) return new JWTCerts(null, null);
    } else {
      // There is no KeyID. This means that the signing certificate MUST be the first certificate in the SVT header chain
      if (jwtCertList.isEmpty()) return new JWTCerts(null, null);
      signerCert = jwtCertList.get(0);
    }
    // Now we have a sign cert. Now collect all certs as supporting certs
    List<X509Certificate> allCertsList = new ArrayList<>();

    supportingCertificates.stream().forEach(cert -> allCertsList.add(cert));
    jwtCertList.stream().forEach(cert -> allCertsList.add(cert));

    // Return collected certs
    return new JWTCerts(signerCert, allCertsList);
  }

  private boolean certMatchKeyId(X509Certificate cert, String keyID, JWSAlgorithm algorithm) {

    try {
      MessageDigest md = MessageDigest.getInstance(SVTAlgoRegistry.getAlgoParams(algorithm).getDigestInstanceName());
      String certHashVal = org.bouncycastle.util.encoders.Base64.toBase64String(md.digest(cert.getEncoded()));
      return keyID.equals(certHashVal);
    } catch (Exception ex){
      return false;
    }
  }

  private List<X509Certificate> getJWTCerts(List<Base64> x509CertChain) {
    if (x509CertChain == null) return new ArrayList<>();

    return x509CertChain.stream()
      .map(base64 -> SVAUtils.getCertOrNull(base64.decode()))
      .filter(x509Certificate -> x509Certificate != null)
      .collect(Collectors.toList());
  }

  private List<String> getSignatureSvaTokens(UnprotectedHeader unprotectedHeader) {
    List<String> svtTokenList = new ArrayList<>();
    if (unprotectedHeader == null){
      return svtTokenList;
    }
    final Object svtObject = unprotectedHeader.getParam("svt");
    if (svtObject instanceof List) {
      List svtList = (List) svtObject;
      for (Object svtItemObject : svtList){
        if (svtItemObject instanceof String){
          svtTokenList.add((String) svtItemObject);
        }
      }
    }
    return svtTokenList;
  }

  @Data
  @AllArgsConstructor
  private class JWTCerts{

    private X509Certificate signingCert;
    private List<X509Certificate> supportingCertList;

  }

}
