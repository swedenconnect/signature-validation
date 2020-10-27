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

/**
 * Implementation of the {@link AbstractSVTSigValClaimsIssuer} class for collecting XML claims data from an XML signature
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLSVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<XMLSigValInput> {

  /** Signature verifier used to validate XML signatures to determine signature validity */
  private final XMLSignatureElementValidator signatureVerifier;

  /** If this is true and signature validation did not provide any policy validation conclusion, then set basic validation level */
  @Setter private boolean defaultBasicValidation = false;

  /**
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @param signatureVerifier verifier of XML signature elements
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws JOSEException JOSE exception
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

    if (isIssueSVT(sigResult)) {
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

  /**
   * Test if a new SVT should be issued for a particular signature
   * @param sigResult The result of validating this signature.
   * @return true if an SVT should be issued (if possible) and false if a null result should be enforced.
   */
  private boolean isIssueSVT(ExtendedXmlSigvalResult sigResult) {

    boolean validationPolicyPassed = false;
    List<PolicyValidationClaims> validationPolicyResultList = sigResult.getValidationPolicyResultList();
    if (validationPolicyResultList != null){
      validationPolicyPassed = validationPolicyResultList.stream()
        .filter(policyValidationClaims -> policyValidationClaims.getRes().equals(ValidationConclusion.PASSED))
        .findFirst()
        .isPresent();
    }

    // We only issue SVT tokes if signature validation passed.
    return validationPolicyPassed;
  }

  /**
   * Obtain the document reference hash values
   * @param refDataMap a data map of signed bytes, keyed by the reference URLs pointing to each XML fragment
   * @param hashAlgoUri algorithm URI for the selected hash algorithm
   * @return List of {@link SignedDataClaims}
   * @throws IOException on error parsing data
   * @throws NoSuchAlgorithmException on unrecognized hash algorithm
   */
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

  /**
   * Obtain signature reference data, uniquely identifies the target XML signature
   * @param signatureData signature data collected for this signature
   * @param hashAlgoUri algorithm URI for the hash algorithm
   * @return {@link SigReferenceClaims}
   * @throws IOException on error parsing data
   * @throws NoSuchAlgorithmException on unrecognized hash algorithm
   */
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
