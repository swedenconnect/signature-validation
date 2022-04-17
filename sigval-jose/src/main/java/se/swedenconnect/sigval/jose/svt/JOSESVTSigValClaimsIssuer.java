/*
 * Copyright (c) 2020. Sweden Connect
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Setter;
import org.bouncycastle.util.encoders.Base64;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;
import se.swedenconnect.sigval.jose.verify.JOSESignatureDataValidator;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.svt.AbstractSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.svt.claims.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of the {@link AbstractSVTSigValClaimsIssuer} class for collecting XML claims data from an XML signature
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JOSESVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<JOSESVTValInput> {

  /** Signature verifier used to validate XML signatures to determine signature validity */
  private final JOSESignatureDataValidator signatureVerifier;

  /** If this is true and signature validation did not provide any policy validation conclusion, then set basic validation level */
  @Setter private boolean defaultBasicValidation = false;

  /**
   * Constructor.
   *
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @param signatureVerifier verifier of XML signature elements
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws JOSEException JOSE exception
   */
  public JOSESVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey,
    List<X509Certificate> certificates, JOSESignatureDataValidator signatureVerifier) throws NoSuchAlgorithmException, JOSEException {
    super(algorithm, privateKey, certificates);
    this.signatureVerifier = signatureVerifier;
  }

  /** {@inheritDoc} */
  @Override protected List<SignatureClaims> verify(JOSESVTValInput sigValInput, String hashAlgoUri) throws Exception {

    JOSESignatureData signatureData = sigValInput.getSignatureData();
    ExtendedJOSESigvalResult sigResult = signatureVerifier.validateSignature(sigValInput.getSignatureData());

    if (isIssueSVT(sigResult)) {
      SignatureClaims claimsData = SignatureClaims.builder()
        .sig_ref(getSigRefData(signatureData, hashAlgoUri))
        .sig_val(getSignaturePolicyValidations(sigResult))
        .sig_data_ref(getDocRefHashes(signatureData, hashAlgoUri))
        .time_val(
          sigResult.getTimeValidationResults().stream()
            .map(timeValidationResult -> extractTimeValClaims(timeValidationResult, hashAlgoUri))
            .filter(this::isVerifiedTime)
            .collect(Collectors.toList())
        )
        .signer_cert_ref(getCertRef(sigResult, hashAlgoUri))
        .build();

      return List.of(claimsData);
    }
    // This signature should not be extended with a new SVT token.
    return null;
  }

  /**
   * Test if a new SVT should be issued for a particular signature
   * @param sigResult The result of validating this signature.
   * @return true if an SVT should be issued (if possible) and false if a null result should be enforced.
   */
  private boolean isIssueSVT(ExtendedJOSESigvalResult sigResult) {

    boolean validationPolicyPassed = false;
    List<PolicyValidationClaims> validationPolicyResultList = sigResult.getValidationPolicyResultList();
    if (validationPolicyResultList != null){
      validationPolicyPassed = validationPolicyResultList.stream()
        .anyMatch(policyValidationClaims -> policyValidationClaims.getRes().equals(ValidationConclusion.PASSED));
    }

    // We only issue SVT tokes if signature validation passed.
    return validationPolicyPassed;
  }

  /**
   * Obtain the document reference hash values. For JSON signatures the reference structure is very simple since the JOSE signature
   * always signs the associated payload. This payload is either embedded or detached. When an embedded payload is signed
   * the reference is simply "payload" and when detached data is signed, the reference is simply "detached".
   *
   * @param signatureData the signature data for the present signature
   * @param hashAlgoUri algorithm URI for the selected hash algorithm
   * @return List of {@link SignedDataClaims}
   * @throws IOException on error parsing data
   * @throws NoSuchAlgorithmException on unrecognized hash algorithm
   */
  private List<SignedDataClaims> getDocRefHashes(JOSESignatureData signatureData, String hashAlgoUri)
    throws IOException, NoSuchAlgorithmException {

    if (signatureData.getPayload() == null){
      throw new IOException("Missing referenced data in signed document. Unable to collect signed data references for SVT");
    }
    List<SignedDataClaims> signedDataClaimsList = new ArrayList<>();
    byte[] signedDocumentBytes = signatureData.getPayload().toBytes();

    MessageDigest digest = DigestAlgorithmRegistry.get(hashAlgoUri).getInstance();
    signedDataClaimsList.add(SignedDataClaims.builder()
      .ref(signatureData.isDetached() ? "detached" : "payload")
      .hash(Base64.toBase64String(digest.digest(signedDocumentBytes)))
      .build());

    // Idea - Fix function in signature context to make it able to extract all referenced data (as opposed to now)
    // Return a map of signed data, mapped by reference URI. as well as the URI representing the root node in SignatureData.

    return signedDataClaimsList;
  }

  /**
   * Obtain signature reference data, uniquely identifies the target signature
   * @param signatureData signature data collected for this signature
   * @param hashAlgoUri algorithm URI for the hash algorithm
   * @return {@link SigReferenceClaims}
   * @throws IOException on error parsing data
   * @throws NoSuchAlgorithmException on unrecognized hash algorithm
   */
  private SigReferenceClaims getSigRefData(JOSESignatureData signatureData, String hashAlgoUri) throws IOException, NoSuchAlgorithmException{
    byte[] signatureBytes = signatureData.getSignatureBytes();
    if (signatureBytes == null || signatureData.getHeader() == null || signatureData.getPayload() == null) {
      throw new IOException("No signature or signed document bytes available");
    }
    final String tbsString = signatureData.getHeader().toBase64URL().toString() + "." + signatureData.getPayload().toBase64URL().toString();
    byte[] signedBytes = tbsString.getBytes(StandardCharsets.UTF_8);
    MessageDigest digest = DigestAlgorithmRegistry.get(hashAlgoUri).getInstance();
    return SigReferenceClaims.builder()
      .sb_hash(Base64.toBase64String(digest.digest(signedBytes)))
      .sig_hash(Base64.toBase64String(digest.digest(signatureBytes)))
      .build();
  }

  /** {@inheritDoc} */
  @Override protected SVTProfile getSvtProfile() {
    return SVTProfile.JWS;
  }
}
