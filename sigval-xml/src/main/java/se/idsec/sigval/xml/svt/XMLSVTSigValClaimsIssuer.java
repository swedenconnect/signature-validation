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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.svt.AbstractSVTSigValClaimsIssuer;
import se.idsec.sigval.svt.claims.*;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class XMLSVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<XMLSigValInput> {
  //TODO  This is the next big task in order to issue SVT for XML docs

  /**  */
  private final XMLSignatureElementValidator signatureVerifier;

  /** If this is true and signature validation did not provide any policy validation conclusion, then set basic validation level */
  @Setter private boolean defaultBasicValidation = false;

  /**
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @throws NoSuchAlgorithmException
   * @throws JOSEException
   */
  public XMLSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey,
    List<X509Certificate> certificates, XMLSignatureElementValidator signatureVerifier) throws NoSuchAlgorithmException, JOSEException {
    super(algorithm, privateKey, certificates);
    this.signatureVerifier = signatureVerifier;
  }

  /** {@inheritDoc} */
  @Override protected List<SignatureClaims> verify(XMLSigValInput sigValInput, String hashAlgoUri) throws Exception {

    SignatureData signatureData = sigValInput.getSignatureData();
    Map<String, byte[]> refDataMap = signatureData.getRefDataMap();
    ExtendedXmlSigvalResult sigResult = signatureVerifier.validateSignature(sigValInput.getSignatureElement(),
      signatureData);

    XMLDocumentSVTMethod svtMethod = sigValInput.getSvtMethod();
    if (isIssueSVT(sigResult, svtMethod)) {
      SignatureClaims claimsData = SignatureClaims.builder()
        .sig_ref(getSigRefData(signatureData, hashAlgoUri))
        .sig_val(getSignaturePolicyValidations(sigResult))
        .sig_data_ref(getDocRefHashes(refDataMap, hashAlgoUri))
        .time_val(
          sigResult.getTimeValidationResults().stream()
            .map(pdfTimeValidationResult -> pdfTimeValidationResult.getTimeValidationClaims())
            .filter(timeValidationClaims -> isVerifiedTime(timeValidationClaims))
            .collect(Collectors.toList())
        )
        .signer_cert_ref(getCertRef(sigResult, hashAlgoUri))
        .build();

      return Arrays.asList(claimsData);
    }
    // This signature should not be extended with a new SVT token.
    return null;
  }

  private boolean isIssueSVT(ExtendedXmlSigvalResult sigResult, XMLDocumentSVTMethod svtMethod) {

    boolean svtValidated = sigResult.getSvtJWT() != null;
    boolean validSig = false;
    List<PolicyValidationClaims> validationPolicyResultList = sigResult.getValidationPolicyResultList();
    if (validationPolicyResultList != null){
      validSig = validationPolicyResultList.stream()
        .filter(policyValidationClaims -> policyValidationClaims.getRes().equals(ValidationConclusion.PASSED))
        .findFirst()
        .isPresent();
    }

    switch (svtMethod){

    case REPLACE:
    case EXTEND:
      return  !(svtValidated && validSig);
    case REPLACE_ALL:
    case EXTEND_ALL:
      return true;
    }
    return false;
  }

  private List<SignedDataClaims> getDocRefHashes(Map<String, byte[]> refDataMap, String hashAlgoUri)
    throws IOException, NoSuchAlgorithmException {

    // Go through all XML references and locate the bytes that were hashed by each reference
    // Throw exception if the reference data cannot be located. This implementation only supports internal references
    List<SignedDataClaims> signedDataClaimsList = new ArrayList<>();
    Set<String> refSet = refDataMap.keySet();
    for(String ref : refSet){
      byte[] signedBytes = refDataMap.get(ref);
      if (signedBytes == null){
        throw new IOException("Missing referenced data in signed document. Unable to collect signed data references for SVT");
      }
      MessageDigest digest = DigestAlgorithmRegistry.get(hashAlgoUri).getInstance();
      signedDataClaimsList.add(SignedDataClaims.builder()
        .ref(ref)
        .hash(Base64.toBase64String(digest.digest(signedBytes)))
        .build());
    }

    // Idea - Fix function in signature context to make it able to extract all referenced data (as opposed to now)
    // Return a map of signed data, mapped by reference URI. as well as the URI representing the root node in SignatureData.

    return signedDataClaimsList;
  }

  private SigReferenceClaims getSigRefData(SignatureData signatureData, String hashAlgoUri) throws IOException, NoSuchAlgorithmException{
    byte[] signatureBytes = signatureData.getSignatureBytes();
    byte[] signedInfoBytes = signatureData.getSignedInfoBytes();
    if (signatureBytes == null || signedInfoBytes == null) throw new IOException("No signature or signed document bytes available");
    MessageDigest digest = DigestAlgorithmRegistry.get(hashAlgoUri).getInstance();
    return SigReferenceClaims.builder()
      .id(signatureData.getSignature().getId())
      .sb_hash(Base64.toBase64String(digest.digest(signedInfoBytes)))
      .sig_hash(Base64.toBase64String(digest.digest(signatureData.getSignatureBytes())))
      .build();
  }

  /** {@inheritDoc} */
  @Override protected SVTProfile getSvtProfile() {
    return SVTProfile.XML;
  }
}
