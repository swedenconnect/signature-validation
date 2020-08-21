package se.idsec.sigval.pdf.timestamp;

import lombok.Getter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.pdf.utils.CMSVerifyUtils;
import se.idsec.sigval.pdf.utils.PDFSVAUtils;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class parse validates and holds the essential information about a PDF timestamp.
 */
@Getter
public class PDFTimeStamp {

  protected byte[] timeStampSigBytes;
  protected byte[] timestampedData;
  protected boolean sigValid;
  protected List<X509Certificate> certList;
  protected X509Certificate sigCert;
  protected TSTInfo tstInfo;
  /** List of policy verifiers determining if the signing certificate is trusted and the time stamp meets all defined policy requirements **/
  protected List<TimeStampPolicyVerifier> tsPolicyVerifiers = new ArrayList<>();
  protected List<PolicyValidationClaims> policyValidationClaimsList = new ArrayList<>();

  public PDFTimeStamp(byte[] timeStampSigBytes, byte[] timestampedData, TimeStampPolicyVerifier... tsPolicyVerifier) throws Exception {
    this.timestampedData = timestampedData;
    this.tsPolicyVerifiers = Arrays.asList(tsPolicyVerifier);
    this.timeStampSigBytes = timeStampSigBytes;
    init();
  }

  public boolean hasVerifiedTimestamp(){
    boolean policyValid = false;
    if (policyValidationClaimsList.isEmpty()){
      policyValid = true;
    }
    for (PolicyValidationClaims policyResult : policyValidationClaimsList){
      if (policyResult.getRes().equals(ValidationConclusion.PASSED)){
        policyValid = true;
      }
    }
    return sigValid && policyValid;
  }

  /**
   * Override this method with extended initializations
   */
  protected void init() throws Exception {
    try {
      CMSSignedDataParser cmsSignedDataParser = CMSVerifyUtils.getCMSSignedDataParser(timeStampSigBytes, timestampedData);
      CMSVerifyUtils.PDFSigCerts sigCerts = CMSVerifyUtils.extractCertificates(cmsSignedDataParser);
      sigCert = sigCerts.getSigCert();
      certList = sigCerts.getChain();
      verifyTsSignature();
      tstInfo = PDFSVAUtils.getPdfDocTSTInfo(timeStampSigBytes);
      verifyTsMessageImprint(cmsSignedDataParser);
      sigValid = true;
      for (TimeStampPolicyVerifier tsPolicyVerifier : tsPolicyVerifiers) {
        policyValidationClaimsList.add(tsPolicyVerifier.verifyTsPolicy(timeStampSigBytes, tstInfo, sigCert, certList));
      }
    }
    catch (Exception ex) {
      sigValid = false;
      return;
    }
  }

  protected void verifyTsMessageImprint(CMSSignedDataParser cmsSignedDataParser) throws Exception {
    MessageImprint messageImprint = tstInfo.getMessageImprint();
    AlgorithmIdentifier tsHashAlgoId = messageImprint.getHashAlgorithm();
    MessageDigest md = DigestAlgorithmRegistry.get(tsHashAlgoId.getAlgorithm()).getInstance();
    byte[] signedDocHash = md.digest(timestampedData);
    if (Arrays.equals(signedDocHash, messageImprint.getHashedMessage())) {
      return;
    }
    throw new RuntimeException("Time stamp message imprint does not match timestamped data");
  }

  /**
   * Validates the timestamp signature
   *
   * <p>
   * To be valid the token must be signed by the passed in certificate and
   * the certificate must be the one referred to by the SigningCertificate
   * attribute included in the hashed attributes of the token. The
   * certificate must also have the ExtendedKeyUsageExtension with only
   * KeyPurposeId.id_kp_timeStamping and have been valid at the time the
   * timestamp was created.
   * </p>
   *
   * @throws Exception if the verification fails
   */
  private void verifyTsSignature() throws Exception {
    byte[] certificateBytes = sigCert.getEncoded();
    X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateBytes);
    SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(certificateHolder);
    TimeStampToken responseToken = new TimeStampToken(ContentInfo.getInstance(new ASN1InputStream(timeStampSigBytes).readObject()));
    responseToken.validate(signerInformationVerifier);
  }

}
