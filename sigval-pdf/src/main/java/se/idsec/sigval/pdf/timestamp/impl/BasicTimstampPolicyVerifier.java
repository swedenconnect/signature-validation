package se.idsec.sigval.pdf.timestamp.impl;

import lombok.Setter;
import org.bouncycastle.asn1.tsp.TSTInfo;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.pdf.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BasicTimstampPolicyVerifier implements TimeStampPolicyVerifier {

  /** Verifier for certificate chains used to sign a timestamp **/
  protected CertificateValidator certificateChainVerifier;
  /** The policy declared as result of passing this policy verifier **/
  @Setter
  private String policy = SigValIdentifiers.SIG_VALIDATION_POLICY_PKIX_VALIDATION;
  /** List of hash algorithm URI:s that are not allowed **/
  @Setter private List<String> hashBlackList = Arrays.asList(DigestAlgorithm.ID_SHA1);

  /**
   * Constructor
   * @param certificateChainVerifier Certificate chain verifier for this validator. This chain verifier MUST perform PKIX path validation with revocation checking.
   */
  public BasicTimstampPolicyVerifier(CertificateValidator certificateChainVerifier) {
    this.certificateChainVerifier = certificateChainVerifier;
  }

  /**
   * Constructor
   * @param certificateChainVerifier Certificate chain verifier for this validator
   * @param policy policy declared as a result of passing or failing this validator tests
   */
  public BasicTimstampPolicyVerifier(CertificateValidator certificateChainVerifier, String policy) {
    this.certificateChainVerifier = certificateChainVerifier;
    this.policy = policy;
  }

  @Override public PolicyValidationClaims verifyTsPolicy(byte[] pdfSigBytes, TSTInfo tstInfo, X509Certificate sigCert,
    List<X509Certificate> certList) {

    PolicyValidationClaims result = PolicyValidationClaims.builder()
      .pol(policy)
      .res(ValidationConclusion.PASSED)
      .build();

    //Check valid hash algo
    try {
        DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(
        tstInfo.getMessageImprint().getHashAlgorithm().getAlgorithm());

      boolean blacklisted = hashBlackList.stream()
        .filter(blacklistDigestAlgo -> digestAlgorithm.getUri().equalsIgnoreCase(blacklistDigestAlgo))
        .collect(Collectors.toList()).size() > 0;
      if (blacklisted){
        result.setRes(ValidationConclusion.FAILED);
        result.setMsg("Using blacklisted hash algorithm for Time Stamp: " + digestAlgorithm.getUri());
        return result;
      }
    }
    catch (Exception ex) {
      result.setRes(ValidationConclusion.FAILED);
      result.setMsg("Error parsing Time Stamp digest algorithm");
      return result;
    }

    // Check certificate trust and validity
    try {
      certificateChainVerifier.validate(sigCert, certList, null);
    } catch (Exception ex) {
      result.setRes(ValidationConclusion.FAILED);
      result.setMsg("Time Stamp signing certificate is not trusted");
    }

    return result;
  }
}
