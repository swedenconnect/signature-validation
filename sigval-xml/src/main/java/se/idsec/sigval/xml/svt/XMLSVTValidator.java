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

package se.idsec.sigval.xml.svt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.opensaml.xmlsec.signature.J;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.utils.SVAUtils;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.validation.SVTValidator;
import se.idsec.sigval.svt.validation.SignatureSVTData;
import se.idsec.sigval.xml.xmlstruct.XMLSigConstants;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public class XMLSVTValidator extends SVTValidator<XMLSigValInput> implements XMLSigConstants {
  /** Certificate chain validator for SVA tokens **/
  private final CertificateValidator svaCertVerifier;

  /**
   * Supporting certificates used to verify the signature on the SVT. A dey ID is valid ref if it matches on of the certificates in this list.
   * If this list is empty, all necessary certificates for verifying the SVT must be present in the header of the SVT.
   */
  private final List<X509Certificate> supportingCertificates;

  public XMLSVTValidator(CertificateValidator svaCertVerifier) {
    this.svaCertVerifier = svaCertVerifier;
    this.supportingCertificates = new ArrayList<>();
  }

  public XMLSVTValidator(CertificateValidator svaCertVerifier, List<X509Certificate> supportingCertificates) {
    this.svaCertVerifier = svaCertVerifier;
    this.supportingCertificates = supportingCertificates != null ? supportingCertificates : new ArrayList<>();
  }

  /**
   * Extract relevant data from the XML signature necessary to validate its consistency with a SVT record.
   *
   * @return a list of {@link SignatureSVTData} object. This list is either empty or contains exactly 1 item.
   * @throws Exception if the process throws an exception
   */
  @Override protected List<SignatureSVTData> getSignatureSVTData(XMLSigValInput signedDataInput) throws Exception {

    /**
     *     First locate the SVT tokens in this signature
     *     Validate them all
     *     Find the most recent one
     *
     *     Check that this signature match the SVT token
     *     Then gather data about this signature
     */

    List<String> svaTokenList = getSignatureSvaTokens(signedDataInput.getSignatureElement());
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

    //Debug
    List<String> svtDates = signedJWTList.stream()
      .map(signedJWT -> SVAUtils.getSVTIssueDate(signedJWT).toString())
      .collect(Collectors.toList());
    String selectedDate = SVAUtils.getSVTIssueDate(mostRecentJwt).toString();

    //TODO Done with validation and picking last. Now collect data

    return null;
  }

  private void verifyJWT(SignedJWT signedJWT) throws Exception {
    JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
    String keyID = signedJWT.getHeader().getKeyID();
    List<X509Certificate> jwtCertList = getJWTCerts(signedJWT.getHeader().getX509CertChain());
    JWTCerts jwtCerts = getAllJwtCerts (algorithm, keyID, jwtCertList);
    if (jwtCerts.getSigningCert() == null) throw new IOException("Unable to locate a SVT signing certificate");
    svaCertVerifier.validate(jwtCerts.getSigningCert(), jwtCerts.getSupportingCertList(), null);
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

  private List<String> getSignatureSvaTokens(Element signatureElement) {
    NodeList sigObjectNodes = signatureElement.getElementsByTagNameNS(XMLDSIG_NS, "Object");
    if (sigObjectNodes == null || sigObjectNodes.getLength() == 0) return new ArrayList<>();

    List<String> svtTokenList = new ArrayList<>();
    for (int i = 0; i< sigObjectNodes.getLength() ; i++){
      try{
        Element sigObjElement = (Element) sigObjectNodes.item(i);
        NodeList svtNodes = sigObjElement.getElementsByTagNameNS(XML_SVT_NS, "SignatureValidationToken");
        if (svtNodes == null || svtNodes.getLength() == 0) continue;
        for (int j = 0; j< svtNodes.getLength() ; j++){
          Element svtElement = (Element) svtNodes.item(j);
          svtTokenList.add(svtElement.getTextContent());
        }
      } catch (Exception ex) {
        log.debug("Error parsing SVT data from signature object node {}", ex.getMessage());
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
