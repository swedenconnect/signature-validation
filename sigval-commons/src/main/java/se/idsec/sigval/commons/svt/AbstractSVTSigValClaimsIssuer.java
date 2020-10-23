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

package se.idsec.sigval.commons.svt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.sigval.commons.data.ExtendedSigValResult;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.*;
import se.idsec.sigval.svt.issuer.SVTIssuer;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Abstract implementation of the SVT signature validation claims issuer providing some basic common functions
 * that may be common to several implementations of SVT issuer. E.g. for XML and PDF
 * @param <T> The signature validation input data class
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractSVTSigValClaimsIssuer<T extends Object> extends SVTIssuer<T> {

  /** If this is true and signature validation did not provide any policy validation conclusion, then set basic validation level */
  @Setter private boolean defaultBasicValidation = false;

  /**
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @throws NoSuchAlgorithmException
   * @throws JOSEException
   */
  public AbstractSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey,
    List<X509Certificate> certificates) throws NoSuchAlgorithmException, JOSEException {
    super(algorithm, privateKey, certificates);
  }

  /**
   * Gets the certificate reference claims for signature validation result
   *
   * <p>Updated logic 2020-10-23. If chain is using certs from the signature, the same chain is stored
   * as cert hashes of individual certs in the same order as if complete certs are stored</p>
   *
   * @param sigResult signature validation result data
   * @param hashAlgoUri the hash algorithm used to hash data
   * @return certificate reference claims
   * @throws CertificateEncodingException certificate errors
   * @throws NoSuchAlgorithmException unsupported algorithm
   * @throws IOException data parsing errors
   */
  protected CertReferenceClaims getCertRef(ExtendedSigValResult sigResult, String hashAlgoUri)
    throws CertificateEncodingException, NoSuchAlgorithmException, IOException{
    X509Certificate signerCertificate = sigResult.getSignerCertificate();
    List<X509Certificate> signatureCertificateChain = sigResult.getSignatureCertificateChain();

    CertificateValidationResult certificateValidationResult;
    try {
      certificateValidationResult = sigResult.getCertificateValidationResult();
    } catch (Exception ex){
      log.error("Unable to obtain the required certificate validation result object", ex);
      throw new IOException("Unable to obtain the required certificate validation result object");
    }

    List<X509Certificate> validatedCertificatePath = certificateValidationResult.getValidatedCertificatePath();
    boolean altered = !isCertPathMatch(validatedCertificatePath, signatureCertificateChain);
    boolean hasValidatedCerts = validatedCertificatePath != null && !validatedCertificatePath.isEmpty();

    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    if (hasValidatedCerts){
      // We have a valid cert path. Store certs as complete certs or as cert hash
      List<String> b64Chain = new ArrayList<>();
      for (X509Certificate chainCert: validatedCertificatePath){
        b64Chain.add(Base64.encodeBase64String(
          // If chain was altered from signature set, provide certs, otherwise provide cert hash
          altered ? chainCert.getEncoded() : md.digest(chainCert.getEncoded())
        ));
      }
      return CertReferenceClaims.builder()
        // If chain was altered from signature set, type is chain, otherwise it is chain_hash
        .type(altered ? CertReferenceClaims.CertRefType.chain.name() : CertReferenceClaims.CertRefType.chain_hash.name())
        .ref(b64Chain)
        .build();
    }

    // We don't have a valid certificate path. Then just return the signing certificate as the evaluated cert path
    String certHash = Base64.encodeBase64String(md.digest(signerCertificate.getEncoded()));
    return CertReferenceClaims.builder()
      .type(CertReferenceClaims.CertRefType.chain_hash.name())
      .ref(Arrays.asList(certHash))
      .build();
  }

  /**
   * Compares the validated path against the signature certificate path and determines if the validated path is altered.
   * @param validatedCertificatePath the validated certificate path
   * @param signatureCertificateChain the certificates obtained from the signature
   * @return true if the signature certificate path contains all certificates of the validated certificate path
   */
  protected boolean isCertPathMatch(List<X509Certificate> validatedCertificatePath, List<X509Certificate> signatureCertificateChain) {
    //The validated certificate path is considered to be equal to the signature certificate collection if all certificates in the validated certificate path
    //is found in the signature certificate list

    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()){
      log.debug("The validated certificate path is null or empty");
      return false;
    }

    for (X509Certificate validatedCert : validatedCertificatePath){
      if (!signatureCertificateChain.contains(validatedCert)){
        log.debug("The validated certificate path is different than the signature certificate path. Signature cert path does not contain {}", validatedCert.getSubjectX500Principal());
        return false;
      }
    }
    log.debug("All certificates in the validated certificate path is found in the signature certificate path");
    return true;
  }

  /**
   * Test if provided time validation claims indicates presence of verified time
   * @param timeValidationClaims time validation claims
   * @return true if time validation claims contains verified time
   */
  protected boolean isVerifiedTime(TimeValidationClaims timeValidationClaims) {
    if (timeValidationClaims == null) return false;
    List<PolicyValidationClaims> policyValidationClaims = timeValidationClaims.getVal();
    if (policyValidationClaims == null || policyValidationClaims.isEmpty()) return false;
    return policyValidationClaims.stream()
      .filter(validation -> validation.getRes().equals(ValidationConclusion.PASSED))
      .findFirst().isPresent();
  }

  /**
   * Returns the signature policy validation claims
   * @param sigResult result of signature validation
   * @return list of policy validation claims
   */
  protected List<PolicyValidationClaims> getSignaturePolicyValidations(ExtendedSigValResult sigResult) {
    List<PolicyValidationClaims> pvList = sigResult.getValidationPolicyResultList();

    if (pvList.isEmpty() && defaultBasicValidation) {
      log.warn("Signature result did not provide any policy signature result. Configured to set basic validation level");
      pvList.add(PolicyValidationClaims.builder()
        .pol(SigValIdentifiers.SIG_VALIDATION_POLICY_BASIC_VALIDATION)
        .res(sigResult.isSuccess() ? ValidationConclusion.PASSED : ValidationConclusion.FAILED)
        .build());
    }

    return pvList;
  }

  /**
   * Create a Base64 hash value string based on input data and hash algorithm URI
   * @param bytes bytes to hash
   * @param hashAlgoUri hash algorithm URI
   * @return Base64 string with hash value
   * @throws NoSuchAlgorithmException unsupported hash algorithm
   */
  protected String getB64Hash(byte[] bytes, String hashAlgoUri) throws NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    return Base64.encodeBase64String(md.digest(bytes));
  }


}
