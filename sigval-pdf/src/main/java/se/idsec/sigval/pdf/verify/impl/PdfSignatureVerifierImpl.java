package se.idsec.sigval.pdf.verify.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
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
import se.idsec.sigval.pdf.timestamp.PDFDocTimeStamp;
import se.idsec.sigval.pdf.timestamp.PDFTimeStamp;
import se.idsec.sigval.pdf.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.pdf.utils.CMSVerifyUtils;
import se.idsec.sigval.pdf.verify.PdfSignatureVerifier;
import se.idsec.sigval.pdf.verify.policy.PDFSigPolicyVerifier;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.TimeValidationClaims;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

@Slf4j
public class PdfSignatureVerifierImpl implements PdfSignatureVerifier {

  /**
   * List of timestamp policy verifiers. A timestamp is regarded as trusted if all present policy validators returns a positive result
   * If no policy verifiers are provided, then all timestamps issued by a trusted key are regarded as valid
   **/
  @Setter
  private TimeStampPolicyVerifier[] timeStampPolicyVerifiers = new TimeStampPolicyVerifier[] {};

  /** List of signature policy verifiers */
  @Setter
  private List<PDFSigPolicyVerifier> sigPolicyVerifiers = new ArrayList<>();

  /** The certificate validator performing certificate path validation */
  private final CertificateValidator certificateValidator;

  public PdfSignatureVerifierImpl(CertificateValidator certificateValidator) {
    this.certificateValidator = certificateValidator;
  }

  public PdfSignatureVerifierImpl(CertificateValidator certificateValidator, TimeStampPolicyVerifier... timeStampPolicyVerifiers) {
    this.timeStampPolicyVerifiers = timeStampPolicyVerifiers;
    this.certificateValidator = certificateValidator;
  }

  public PdfSignatureVerifierImpl(CertificateValidator certificateValidator, PDFSigPolicyVerifier pdfSigPolicyVerifier, TimeStampPolicyVerifier... timeStampPolicyVerifiers) {
    this.sigPolicyVerifiers = Arrays.asList(pdfSigPolicyVerifier);
    this.timeStampPolicyVerifiers = timeStampPolicyVerifiers;
    this.certificateValidator = certificateValidator;
  }

  public PdfSignatureVerifierImpl(CertificateValidator certificateValidator, List<PDFSigPolicyVerifier> pdfSigPolicyVerifiers, TimeStampPolicyVerifier... timeStampPolicyVerifiers) {
    this.sigPolicyVerifiers = pdfSigPolicyVerifiers;
    this.timeStampPolicyVerifiers = timeStampPolicyVerifiers;
    this.certificateValidator = certificateValidator;
  }

  @Override public ExtendedPdfSigValResult verifySignature(PDSignature signature, byte[] pdfDocument,
    List<PDFDocTimeStamp> documentTimestamps) throws Exception {
    ExtendedPdfSigValResult sigResult = new ExtendedPdfSigValResult();
    sigResult.setPdfSignature(signature);
    sigResult.setSignedData(signature.getContents(pdfDocument));
    CMSSignedDataParser cmsSignedDataParser = CMSVerifyUtils.getCMSSignedDataParser(signature, pdfDocument);
    CMSTypedStream signedContent = cmsSignedDataParser.getSignedContent();
    signedContent.drain();
    CMSVerifyUtils.PDFSigCerts pdfSigCerts = CMSVerifyUtils.extractCertificates(cmsSignedDataParser);
    SignerInformation signerInformation = cmsSignedDataParser.getSignerInfos().iterator().next();
    sigResult.setSignerCertificate(pdfSigCerts.getSigCert());
    sigResult.setSignatureCertificateChain(pdfSigCerts.getChain());
    X509CertificateHolder certHolder = new X509CertificateHolder(pdfSigCerts.getSigCert().getEncoded());
    SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder);
    // Verify signature
    try {
      sigResult.setSuccess(signerInformation.verify(signerInformationVerifier));
    }
    catch (Exception ex) {
      sigResult.setSuccess(false);
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      sigResult.setStatusMessage("Signature validation failure: " + ex.getMessage());
    }

    // Get Public key params and other data
    CMSVerifyUtils.getPkParams(sigResult.getSignerCertificate().getPublicKey(), sigResult);
    //DigestAlgorithm signerInfoHashAlgo = DigestAlgorithmRegistry.get(signerInformation.getDigestAlgOID());
    //sigResult.setD(signerInfoHashAlgo);
    String encryptionAlgOID = signerInformation.getEncryptionAlgOID();
    String algorithmURI = PDFAlgorithmRegistry.getAlgorithmURI(new ASN1ObjectIdentifier(encryptionAlgOID),
      new ASN1ObjectIdentifier(signerInformation.getDigestAlgOID()));
    sigResult.setSignatureAlgorithm(algorithmURI);
    Attribute cmsAlgoProtAttr = signerInformation.getSignedAttributes()
      .get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_CMS_ALGORITHM_PROTECTION));
    CMSVerifyUtils.getCMSAlgoritmProtectionData(cmsAlgoProtAttr, sigResult);

    // Check algorithm consistency
    if (!CMSVerifyUtils.checkAlgoritmConsistency(sigResult)) {
      sigResult.setSuccess(false);
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      sigResult.setStatusMessage("Signature was verified but with inconsistent Algoritm declarations or unsupported algoritms");
    }

    // Check Pades properties
    if (sigResult.isSuccess()) {
      verifyPadesProperties(signerInformation, sigResult);
    }

    // Verify timestamps
    try {
      sigResult.setSignatureTimeStampList(checkTimeStamps(signerInformation));
    }
    catch (Exception ex) {
      sigResult.setSignatureTimeStampList(new ArrayList<>());
      Logger.getLogger(PdfSignatureVerifier.class.getName()).warning("Error parsing signature timestamps: " + ex.getMessage());
    }

    // Add timestamp results
    addVerifiedTimes(sigResult, documentTimestamps);

    try {
      CertificateValidationResult validationResult = certificateValidator.validate(sigResult.getSignerCertificate(),
        sigResult.getSignatureCertificateChain(), null);
      sigResult.setCertificateValidationResult(validationResult);
    } catch (Exception ex){
      if (ex instanceof ExtendedCertPathValidatorException){
        ExtendedCertPathValidatorException extEx = (ExtendedCertPathValidatorException) ex;
        sigResult.setCertificateValidationResult(extEx.getPathValidationResult());
        sigResult.setStatusMessage(extEx.getMessage());
      } else {
        sigResult.setStatusMessage("Signer certificate failed path validation");
      }
      sigResult.setSuccess(false);
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_SIGNER_INVALID);
      sigResult.setException(ex);
    }

    // Finally perform signature validation policy verification
    List<PolicyValidationClaims> policyValidationClaimsList = new ArrayList<>();
    for (PDFSigPolicyVerifier policyVerifier : sigPolicyVerifiers) {
      policyValidationClaimsList.add(policyVerifier.validatePolicy(sigResult));
    }
    sigResult.setValidationPolicyResultList(policyValidationClaimsList);

    return sigResult;
  }

  @Override public List<PDFDocTimeStamp> verifyDocumentTimestamps(List<PDSignature> documentTimestampSignatures, byte[] pdfDocument) {
    List<PDFDocTimeStamp> docTimeStampList = new ArrayList<>();
    for (PDSignature sig : documentTimestampSignatures) {
      try {
        PDFDocTimeStamp docTs = new PDFDocTimeStamp(sig, pdfDocument, timeStampPolicyVerifiers);
        docTimeStampList.add(docTs);
      }
      catch (Exception e) {
        log.warn("Exception while processing document timestamp" + e.getMessage());
      }
    }
    return docTimeStampList;
  }

  @Override public CertificateValidator getCertificateValidator() {
    return certificateValidator;
  }

  private List<PDFTimeStamp> checkTimeStamps(SignerInformation signerInformation)
    throws Exception {
    AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
    if (unsignedAttributes == null) {
      return new ArrayList<>();
    }
    ASN1EncodableVector timeStampsASN1 = unsignedAttributes.getAll(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_TIMESTAMP_ATTRIBUTE));
    if (timeStampsASN1.size() == 0) {
      return new ArrayList<>();
    }
    List<PDFTimeStamp> timeStampList = new ArrayList<>();
    for (int i = 0; i < timeStampsASN1.size(); i++) {
      Attribute tsAttribute = Attribute.getInstance(timeStampsASN1.get(i));
      byte[] tsContentInfoBytes = ContentInfo.getInstance(tsAttribute.getAttrValues().getObjectAt(0).toASN1Primitive()).getEncoded("DER");
      PDFTimeStamp timeStamp = new PDFTimeStamp(tsContentInfoBytes, signerInformation.getSignature(), timeStampPolicyVerifiers);
      timeStampList.add(timeStamp);
    }
    return timeStampList;
  }

  private void addVerifiedTimes(ExtendedPdfSigValResult directVerifyResult, List<PDFDocTimeStamp> docTimeStampList) {
    List<TimeValidationClaims> timeValidationClaimsList = directVerifyResult.getTimeValidationClaimsList();
    directVerifyResult.getSignatureTimeStampList().stream()
      //Only if timestamp is valid
      .filter(pdfTimeStamp -> pdfTimeStamp.hasVerifiedTimestamp())
      .map(pdfTimeStamp -> getVerifiedTimeFromTimeStamp(pdfTimeStamp, SigValIdentifiers.TIME_VERIFICATION_TYPE_PDF_SIG_TIMESTAMP))
      //Remove null results
      .filter(verifiedTime -> verifiedTime != null)
      .forEach(verifiedTime -> timeValidationClaimsList.add(verifiedTime));

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
  }

  private TimeValidationClaims getVerifiedTimeFromTimeStamp(PDFTimeStamp pdfTimeStamp, String type) {
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

  public void verifyPadesProperties(SignerInformation signer, ExtendedPdfSigValResult sigResult) {
    try {
      AttributeTable signedAttributes = signer.getSignedAttributes();
      Attribute essSigningCertV2Attr = signedAttributes.get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V2));
      Attribute signingCertAttr = signedAttributes.get(new ASN1ObjectIdentifier(PDFObjectIdentifiers.ID_AA_SIGNING_CERTIFICATE_V1));

      if (essSigningCertV2Attr == null && signingCertAttr == null) {
        sigResult.setPades(false);
        sigResult.setInvalidSignCert(false);
        return;
      }

      //Start assuming that PAdES validation is non-successful
      sigResult.setPades(true);
      sigResult.setInvalidSignCert(true);
      sigResult.setStatus(SignatureValidationResult.Status.ERROR_SIGNER_INVALID);
      sigResult.setSuccess(false);

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
      sigResult.setSuccess(true);

    }
    catch (Exception e) {
      sigResult.setStatusMessage("Exception while examining Pades signed cert attr: " + e.getMessage());
    }
  }

}
