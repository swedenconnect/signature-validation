package se.idsec.sigval.pdf.verify.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.signservice.security.sign.pdf.configuration.PDFObjectIdentifiers;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.data.PdfTimeValidationResult;
import se.idsec.sigval.pdf.timestamp.PDFDocTimeStamp;
import se.idsec.sigval.pdf.timestamp.PDFTimeStamp;
import se.idsec.sigval.pdf.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.pdf.timestamp.impl.BasicTimstampPolicyVerifier;
import se.idsec.sigval.pdf.utils.CMSVerifyUtils;
import se.idsec.sigval.pdf.verify.PDFSingleSignatureVerifier;
import se.idsec.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.idsec.sigval.pdf.pdfstruct.PDFSignatureContext;
import se.idsec.sigval.pdf.verify.policy.PolicyValidationResult;
import se.idsec.sigval.pdf.verify.policy.impl.BasicPdfSignaturePolicyValidator;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.TimeValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Implements verification of a PDF signature, validating the actual signature and signing certificates
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PDFSingleSignatureVerifierImpl implements PDFSingleSignatureVerifier {

  /**
   * List of timestamp policy verifiers. A timestamp is regarded as trusted if all present policy validators returns a positive result
   * If no policy verifiers are provided, then all timestamps issued by a trusted key are regarded as valid
   **/
  @Setter
  private TimeStampPolicyVerifier timeStampPolicyVerifier;

  /** Signature policy verifier */
  private final PDFSignaturePolicyValidator sigPolicyVerifier;

  /** The certificate validator performing certificate path validation */
  private final CertificateValidator certificateValidator;

  /**
   * Constructor
   *
   * @param certificateValidator the validator used to verify signing certificate chains
   */
  public PDFSingleSignatureVerifierImpl(CertificateValidator certificateValidator) {
    this.certificateValidator = certificateValidator;
    this.timeStampPolicyVerifier = new BasicTimstampPolicyVerifier(certificateValidator);
    this.sigPolicyVerifier = new BasicPdfSignaturePolicyValidator();
  }

  /**
   * Constructor
   *
   * @param certificateValidator    the validator used to verify signing certificate chains
   * @param timeStampPolicyVerifier verifier validating time stamps to a defined policy
   */
  public PDFSingleSignatureVerifierImpl(CertificateValidator certificateValidator, TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
    this.certificateValidator = certificateValidator;
    this.sigPolicyVerifier = new BasicPdfSignaturePolicyValidator();
  }

  /**
   * Constructor
   *
   * @param certificateValidator        the validator used to verify signing certificate chains
   * @param timeStampPolicyVerifier     verifier validating time stamps to a defined policy
   * @param pdfSignaturePolicyValidator verifier of the signature results according to a defined policy
   */
  public PDFSingleSignatureVerifierImpl(CertificateValidator certificateValidator, PDFSignaturePolicyValidator pdfSignaturePolicyValidator,
    TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.certificateValidator = certificateValidator;
    this.sigPolicyVerifier = pdfSignaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
  }

  /** {@inheritDoc} */
  @Override
  public ExtendedPdfSigValResult verifySignature(PDSignature signature, byte[] pdfDocument,
    List<PDFDocTimeStamp> documentTimestamps, PDFSignatureContext signatureContext) throws Exception {
    ExtendedPdfSigValResult sigResult = new ExtendedPdfSigValResult();
    sigResult.setPdfSignature(signature);
    sigResult.setSignedData(signature.getContents(pdfDocument));
    sigResult.setCoversDocument(signatureContext.isCoversWholeDocument(signature));
    byte[] unsignedDocument = null;
    try {
      unsignedDocument = signatureContext.getSignedDocument(signature);
    }
    catch (Exception ex) {
      log.debug("The document signed by this signature is not available");
    }
    sigResult.setSignedDocument(unsignedDocument);
    CMSSignedDataParser cmsSignedDataParser = CMSVerifyUtils.getCMSSignedDataParser(signature, pdfDocument);
    CMSTypedStream signedContent = cmsSignedDataParser.getSignedContent();
    signedContent.drain();
    CMSVerifyUtils.PDFSigCerts pdfSigCerts = CMSVerifyUtils.extractCertificates(cmsSignedDataParser);
    SignerInformation signerInformation = cmsSignedDataParser.getSignerInfos().iterator().next();
    sigResult.setSignerCertificate(pdfSigCerts.getSigCert());
    sigResult.setSignatureCertificateChain(pdfSigCerts.getChain());
    X509CertificateHolder certHolder = new X509CertificateHolder(pdfSigCerts.getSigCert().getEncoded());
    SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder);

    // Verify signature value against document data
    try {
      sigResult.setStatus(signerInformation.verify(signerInformationVerifier)
        ? SignatureValidationResult.Status.SUCCESS
        : SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
    }
    catch (Exception ex) {
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      sigResult.setException(ex);
      sigResult.setStatusMessage("Signature validation failure: " + ex.getMessage());
      log.debug("Signature validation failure {}", ex.getMessage());
      return sigResult;
    }

    // Get algorithms and public key related data
    CMSVerifyUtils.getPkParams(sigResult.getSignerCertificate().getPublicKey(), sigResult);
    ASN1ObjectIdentifier signAlgoOid = new ASN1ObjectIdentifier(signerInformation.getEncryptionAlgOID());
    ASN1ObjectIdentifier digestAlgoOid = new ASN1ObjectIdentifier(signerInformation.getDigestAlgOID());
    sigResult.setCmsSignatureAlgo(signAlgoOid);
    sigResult.setCmsDigestAlgo(digestAlgoOid);
    String algorithmURI = null;
    try {
      algorithmURI = PDFAlgorithmRegistry.getAlgorithmURI(signAlgoOid, digestAlgoOid);
    }
    catch (Exception ex) {
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      sigResult.setException(ex);
      sigResult.setStatusMessage("Signature was signed with unsupported algorithms");
      log.debug("Signature was signed with unsupported algorithms: Signature algo {}, Digest algo {}", signAlgoOid, digestAlgoOid);
      return sigResult;
    }
    sigResult.setSignatureAlgorithm(algorithmURI);
    AttributeTable signedAttributes = signerInformation.getSignedAttributes();
    Attribute cmsAlgoProtAttr = signedAttributes.get(PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect);
    //    Attribute cmsAlgoProtAttr = signedAttributes.get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_CMS_ALGORITHM_PROTECTION));
    CMSVerifyUtils.getCMSAlgoritmProtectionData(cmsAlgoProtAttr, sigResult);

    // Check algorithm consistency
    if (!CMSVerifyUtils.checkAlgoritmConsistency(sigResult)) {
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      sigResult.setException(new SignatureException("Signature algorithm mismatch in CMS algorithm protection extension"));
      sigResult.setStatusMessage("Signature algorithm mismatch in CMS algorithm protection extension");
      log.debug("CMS algo protection mismatch: Signature algo {}, Digest algo {}, CMS-AP Signature algo {}, CMS-AP Digest algo {}",
        signAlgoOid, digestAlgoOid, sigResult.getCmsAlgoProtectionSigAlgo(), sigResult.getCmsAlgoProtectionDigestAlgo());
      return sigResult;
    }

    // Check Pades properties
    if (sigResult.isSuccess()) {
      verifyPadesProperties(signerInformation, sigResult);
    }

    //Check claimed signing time
    sigResult.setClaimedSigningTime(
      getClaimedSigningTime(signature.getSignDate(), signedAttributes.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime)));

    // Verify timestamps
    try {
      sigResult.setTimeValidationResults(checkTimeStamps(signerInformation));
    }
    catch (Exception ex) {
      sigResult.setTimeValidationResults(new ArrayList<>());
      Logger.getLogger(PDFSingleSignatureVerifier.class.getName()).warning("Error parsing signature timestamps: " + ex.getMessage());
    }

    // Add timestamp results
    addVerifiedTimes(sigResult, documentTimestamps);

    try {
      CertificateValidationResult validationResult = certificateValidator.validate(sigResult.getSignerCertificate(),
        sigResult.getSignatureCertificateChain(), null);
      sigResult.setCertificateValidationResult(validationResult);
    }
    catch (Exception ex) {
      if (ex instanceof ExtendedCertPathValidatorException) {
        ExtendedCertPathValidatorException extEx = (ExtendedCertPathValidatorException) ex;
        sigResult.setCertificateValidationResult(extEx.getPathValidationResult());
        sigResult.setStatusMessage(extEx.getMessage());
      }
      else {
        sigResult.setStatusMessage("Signer certificate failed path validation");
      }
      //sigResult.setSuccess(false);
      //sigResult.setStatus(SignatureValidationResult.Status.ERROR_SIGNER_INVALID);
      sigResult.setException(ex);
    }

    // Let the signature policy verifier determine the final result path validation
    // The signature policy verifier may accept a revoked cert if signature is timestamped
    PolicyValidationResult policyValidationResult = sigPolicyVerifier.validatePolicy(sigResult, signatureContext);
    PolicyValidationClaims policyValidationClaims = policyValidationResult.getPolicyValidationClaims();
    if (!policyValidationClaims.getRes().equals(ValidationConclusion.PASSED)) {
      sigResult.setStatus(policyValidationResult.getStatus());
      sigResult.setStatusMessage(policyValidationClaims.getMsg());
      sigResult.setException(new SignatureException(policyValidationClaims.getMsg()));
    }
    sigResult.setValidationPolicyResultList(Arrays.asList(policyValidationClaims));

    return sigResult;
  }

  /**
   * Extracts the claimed signing time from a PDF signature
   *
   * @param dictionalyDignDate    the signing time obtained from the signature dictionary or null of no such time exist
   * @param signedAttrSigningTime the signing time attribute from signed attributes
   * @return signing time in milliseconds from epoc time
   */
  private Date getClaimedSigningTime(Calendar dictionalyDignDate, Attribute signedAttrSigningTime) {
    if (signedAttrSigningTime == null && dictionalyDignDate == null) {
      log.debug("No time information available as claimed signing time");
      return null;
    }
    if (signedAttrSigningTime == null) {
      log.debug("No claimed signing time in signed attributes. Using time from signature dictionary");
      return dictionalyDignDate.getTime();
    }
    ASN1Encodable[] attributeValues = signedAttrSigningTime.getAttributeValues();
    try {
      ASN1UTCTime signingTime = ASN1UTCTime.getInstance(attributeValues[0]);
      log.debug("Found UTC claimed signing time in signed attributes");
      return signingTime.getAdjustedDate();
    }
    catch (Exception ex) {
      log.debug("Unable to extract UTCTime from signing time signed attributes. Attempting Generalized time");
    }
    try {
      ASN1GeneralizedTime signingTime = ASN1GeneralizedTime.getInstance(attributeValues[0]);
      log.debug("Found Generalized time claimed signing time in signed attributes");
      return signingTime.getDate();
    }
    catch (Exception ex) {
      log.debug("Unable to extract time information from signing time signed attributes.");
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override public List<PDFDocTimeStamp> verifyDocumentTimestamps(List<PDSignature> documentTimestampSignatures, byte[] pdfDocument) {
    List<PDFDocTimeStamp> docTimeStampList = new ArrayList<>();
    for (PDSignature sig : documentTimestampSignatures) {
      try {
        PDFDocTimeStamp docTs = new PDFDocTimeStamp(sig, pdfDocument, timeStampPolicyVerifier);
        docTimeStampList.add(docTs);
      }
      catch (Exception e) {
        log.warn("Exception while processing document timestamp" + e.getMessage());
      }
    }
    return docTimeStampList;
  }

  /** {@inheritDoc} */
  @Override public CertificateValidator getCertificateValidator() {
    return certificateValidator;
  }

  /**
   * Validates the timestamp embedded inside the target signature
   *
   * @param signerInformation signerInformation holding the timestamp
   * @return a list of timestamps found in the signature data
   * @throws Exception on errors
   */
  private List<PdfTimeValidationResult> checkTimeStamps(final SignerInformation signerInformation)
    throws Exception {
    AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
    if (unsignedAttributes == null) {
      return new ArrayList<>();
    }
    ASN1EncodableVector timeStampsASN1 = unsignedAttributes.getAll(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_TIMESTAMP_ATTRIBUTE));
    if (timeStampsASN1.size() == 0) {
      return new ArrayList<>();
    }
    List<PdfTimeValidationResult> timeStampList = new ArrayList<>();
    for (int i = 0; i < timeStampsASN1.size(); i++) {
      Attribute tsAttribute = Attribute.getInstance(timeStampsASN1.get(i));
      byte[] tsContentInfoBytes = ContentInfo.getInstance(tsAttribute.getAttrValues().getObjectAt(0).toASN1Primitive()).getEncoded("DER");
      PDFTimeStamp timeStamp = new PDFTimeStamp(tsContentInfoBytes, signerInformation.getSignature(), timeStampPolicyVerifier);
      timeStampList.add(new PdfTimeValidationResult(null, timeStamp.getCertificateValidationResult(), timeStamp));
    }
    return timeStampList;
  }

  /**
   * Add verified timestamps to the signature validation results
   *
   * @param directVerifyResult the verification results including result data from time stamps embedded in the signature
   * @param docTimeStampList   list of document timestamps provided with this signed PDF document
   */
  private void addVerifiedTimes(ExtendedPdfSigValResult directVerifyResult, final List<PDFDocTimeStamp> docTimeStampList) {
    List<PdfTimeValidationResult> timeValidationResults = new ArrayList<>();

    // Loop through direct validation results and add signature timestamp results
    for (PdfTimeValidationResult result : directVerifyResult.getTimeValidationResults()) {
      PDFTimeStamp timeStamp = result.getTimeStamp();
      //      if (timeStamp != null && timeStamp.hasVerifiedTimestamp()){
      TimeValidationClaims timeValidationClaims = getVerifiedTimeFromTimeStamp(timeStamp,
        SigValIdentifiers.TIME_VERIFICATION_TYPE_PDF_SIG_TIMESTAMP);
      if (timeValidationClaims != null) {
        timeValidationResults.add(new PdfTimeValidationResult(
          timeValidationClaims, timeStamp.getCertificateValidationResult(), timeStamp));
      }
      //      }
    }

/*
    List<TimeValidationClaims> timeValidationClaimsList = directVerifyResult.getTimeValidationResults();
    directVerifyResult.getTimeValidationResults().stream()
      .map(pdfTimeValidationResult -> pdfTimeValidationResult.getTimeStamp())
      //Only if timestamp is valid
      .filter(pdfTimeStamp -> pdfTimeStamp != null && pdfTimeStamp.hasVerifiedTimestamp())
      .map(pdfTimeStamp -> getVerifiedTimeFromTimeStamp(pdfTimeStamp, SigValIdentifiers.TIME_VERIFICATION_TYPE_PDF_SIG_TIMESTAMP))
      //Remove null results
      .filter(verifiedTime -> verifiedTime != null)
      .forEach(verifiedTime -> timeValidationClaimsList.add(verifiedTime));
*/

    // Loop through document timestamps
    for (PDFDocTimeStamp docTimeStamp : docTimeStampList) {
      //      if (docTimeStamp != null && docTimeStamp.hasVerifiedTimestamp()){
      TimeValidationClaims timeValidationClaims = getVerifiedTimeFromTimeStamp(docTimeStamp,
        SigValIdentifiers.TIME_VERIFICATION_TYPE_PDF_DOC_TIMESTAMP);
      if (timeValidationClaims != null) {
        timeValidationResults.add(new PdfTimeValidationResult(
          timeValidationClaims, docTimeStamp.getCertificateValidationResult(), docTimeStamp));
      }
      //      }
    }

/*
    // Add document timestamp
    docTimeStampList.stream()
      //Only if signature is covered by timestamp
      .filter(pdfDocTimeStamp -> pdfDocTimeStamp.isSignatureCovered(directVerifyResult.getPdfSignature()))
      //Only if timestamp is valid
      .filter(pdfDocTimeStamp -> pdfDocTimeStamp.hasVerifiedTimestamp())
      .map(pdfTimeStamp -> getVerifiedTimeFromTimeStamp(pdfTimeStamp, SigValIdentifiers.TIME_VERIFICATION_TYPE_PDF_DOC_TIMESTAMP))
      //Remove null results
      .filter(verifiedTime -> verifiedTime != null)
      .forEach(verifiedTime -> timeValidationClaimsList.add(verifiedTime));
*/
    directVerifyResult.setTimeValidationResults(timeValidationResults);
  }

  private TimeValidationClaims getVerifiedTimeFromTimeStamp(final PDFTimeStamp pdfTimeStamp, final String type) {
    try {
      TimeValidationClaims timeValidationClaims = TimeValidationClaims.builder()
        .id(pdfTimeStamp.getTstInfo().getSerialNumber().getValue().toString(16))
        .iss(pdfTimeStamp.getSigCert().getSubjectX500Principal().toString())
        .time(pdfTimeStamp.getTstInfo().getGenTime().getDate().getTime() / 1000)
        .type(type)
        .val(pdfTimeStamp.getPolicyValidationClaimsList())
        .build();
      return timeValidationClaims;
    }
    catch (Exception ex) {
      return null;
    }
  }

  /**
   * Verifies the PAdES properties of this signature
   *
   * @param signer    SignerInformation of this signature
   * @param sigResult signature result object for this signature
   */
  public void verifyPadesProperties(final SignerInformation signer, ExtendedPdfSigValResult sigResult) {
    try {
      AttributeTable signedAttributes = signer.getSignedAttributes();
      Attribute essSigningCertV2Attr = signedAttributes.get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V2));
      Attribute signingCertAttr = signedAttributes.get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V1));

      if (essSigningCertV2Attr == null && signingCertAttr == null) {
        sigResult.setEtsiAdes(false);
        sigResult.setInvalidSignCert(false);
        return;
      }

      //Start assuming that PAdES validation is non-successful
      sigResult.setEtsiAdes(true);
      sigResult.setInvalidSignCert(true);
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_SIGNER_INVALID);

      DEROctetString certHashOctStr = null;
      DigestAlgorithm hashAlgo = null;

      if (essSigningCertV2Attr != null) {
        ASN1Sequence essCertIDv2Sequence = CMSVerifyUtils.getESSCertIDSequence(essSigningCertV2Attr);
        /**
         * ESSCertIDv2 ::=  SEQUENCE {
         *   hashAlgorithm           AlgorithmIdentifier
         *                   DEFAULT {algorithm id-sha256},
         *   certHash                 Hash,
         *   issuerSerial             IssuerSerial OPTIONAL
         * }
         *
         */
        // BUG Fix 190121. Hash algorithm is optional and defaults to SHA256. Fixed from being treated as mandatory.
        int certHashIndex = 0;
        if (essCertIDv2Sequence.getObjectAt(0) instanceof ASN1Sequence) {
          // Hash algo identifier id present. Get specified value and set certHashIndex index to 1.
          ASN1Sequence algoSeq = (ASN1Sequence) essCertIDv2Sequence.getObjectAt(0); //Holds sequence of OID and algo params
          ASN1ObjectIdentifier algoOid = (ASN1ObjectIdentifier) algoSeq.getObjectAt(0);
          hashAlgo = DigestAlgorithmRegistry.get(algoOid);
          certHashIndex = 1;
        }
        else {
          // Hash algo identifier is not present. Set hash algo to the default SHA-256 value and keep certHashIndex index = 0.
          hashAlgo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA256);
        }
        certHashOctStr = (DEROctetString) essCertIDv2Sequence.getObjectAt(certHashIndex);
      }
      else {
        if (signingCertAttr != null) {
          ASN1Sequence essCertIDSequence = CMSVerifyUtils.getESSCertIDSequence(signingCertAttr);
          /**
           * ESSCertID ::=  SEQUENCE {
           *      certHash                 Hash,
           *      issuerSerial             IssuerSerial OPTIONAL
           * }
           */
          certHashOctStr = (DEROctetString) essCertIDSequence.getObjectAt(0);
          hashAlgo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA1);
        }
      }

      if (hashAlgo == null || certHashOctStr == null) {
        sigResult.setStatusMessage("Unsupported hash algo for ESS-SigningCertAttributeV2");
        return;
      }

      MessageDigest md = hashAlgo.getInstance();
      md.update(sigResult.getSignerCertificate().getEncoded());
      byte[] certHash = md.digest();

      //            //Debug
      //            String certHashStr = String.valueOf(Base64Coder.encode(certHash));
      //            String expectedCertHashStr = String.valueOf(Base64Coder.encode(certHashOctStr.getOctets()));
      if (!Arrays.equals(certHash, certHashOctStr.getOctets())) {
        sigResult.setStatusMessage("Cert Hash mismatch");
        return;
      }

      //PadES validation was successful
      sigResult.setInvalidSignCert(false);
      sigResult.setStatus(SignatureValidationResult.Status.SUCCESS);

    }
    catch (Exception e) {
      sigResult.setStatusMessage("Exception while examining Pades signed cert attr: " + e.getMessage());
    }
  }

}
