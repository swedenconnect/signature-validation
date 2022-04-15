/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.pdf.verify.impl;

import com.nimbusds.jwt.SignedJWT;
import org.apache.xmlbeans.XmlString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.etsi.uri.x01903.v13.DigestAlgAndValueType;
import org.etsi.uri.x19102.v12.*;
import org.w3.x2000.x09.xmldsig.DigestMethodType;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.report.data.MainIndication;
import se.swedenconnect.sigval.report.data.SubIndication;
import se.swedenconnect.sigval.report.impl.AbstractSigValReportGenerator;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;

import java.io.IOException;

/**
 * PDF Implementation of the Signature validation report generator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefalutPDFSigValReportGenerator extends AbstractSigValReportGenerator<ExtendedPdfSigValResult> {

  public DefalutPDFSigValReportGenerator() {
    super(DigestAlgorithm.ID_SHA256);
  }

  public DefalutPDFSigValReportGenerator(String defaultHashAlgo) {
    super(defaultHashAlgo);
  }

  /**
   * Get signature quality from the signature validation result
   *
   * @param sigValResult The result of signature validation
   * @return signature quality
   */
  @Override protected String getSignatureQuality(ExtendedPdfSigValResult sigValResult) {
    boolean validEtsiBaseline = sigValResult.isEtsiAdes() && !sigValResult.isInvalidSignCert();
    if (validEtsiBaseline) {
      return "urn:cef:dss:signatureQualification:AdESig";
    }
    return "urn:cef:dss:signatureQualification:notApplicable";
  }

  /**
   * Get the signature validation process identifier for this signature validation process
   *
   * @param sigValResult The result data from signature validation
   * @param pol          the policy used to do the original signature validation
   * @return the signature validation process identifier to be included in the signature validation report
   */
  @Override protected SignatureValidationProcessType getSignatureValidationProcess(ExtendedPdfSigValResult sigValResult, String pol) {
    return defaultGetSignatureValidationProcess(sigValResult, pol);
  }

  /**
   * Get the signed data object format for this signature validation result
   *
   * @return Signed data object format
   */
  @Override protected SADataObjectFormatType getDataObjectFormat() {
    SADataObjectFormatType saDataObjectFormatType = SADataObjectFormatType.Factory.newInstance();
    saDataObjectFormatType.setContentType("1.2.840.113549.1.7.1");
    saDataObjectFormatType.setMimeType("application/pdf");
    return saDataObjectFormatType;
  }

  /**
   * Get the DTBSR (Data to be signed representation) hash value and hash algorithm according the document profile
   *
   * @param sigValResult signature validation result
   * @param hashAlgoId   hash algorithm id
   * @return digest value and algorithm for the DTBSR
   */
  @Override protected DigestAlgAndValueType getSignatureDtbsDigestAndValue(ExtendedPdfSigValResult sigValResult, String hashAlgoId)
    throws IOException {

    SignerInfo signerInfo = getSignerInfo(sigValResult);
    try {
      byte[] sigAttrsEncBytes = signerInfo.getAuthenticatedAttributes().getEncoded("DER");
      byte[] dtbsrHash = DigestAlgorithmRegistry.get(hashAlgoId).getInstance().digest(sigAttrsEncBytes);
      DigestAlgAndValueType digestAlgAndValueType = DigestAlgAndValueType.Factory.newInstance();
      digestAlgAndValueType.setDigestValue(dtbsrHash);
      DigestMethodType digestMethodType = DigestMethodType.Factory.newInstance();
      digestMethodType.setAlgorithm(hashAlgoId);
      digestAlgAndValueType.setDigestMethod(digestMethodType);
      return digestAlgAndValueType;
    }
    catch (Exception ex) {
      throw (ex instanceof IOException) ? (IOException) ex : new IOException(ex);
    }
  }

  /**
   * Get the signature value
   *
   * @param sigValResult
   * @return
   */
  @Override protected byte[] getSignatureValue(ExtendedPdfSigValResult sigValResult) throws IOException {

    SignerInfo signerInfo = getSignerInfo(sigValResult);
    byte[] signatureBytes = signerInfo.getEncryptedDigest().getOctets();
    return signatureBytes;

  }

  /**
   * Apply the final validation checks against any policy provided by the profile
   *
   * @param signatureValidationReportType signature validation report data before policy check
   * @param sigValResult                  signature validation result
   */
  @Override protected void applyValidationPolicy(SignatureValidationReportType signatureValidationReportType,
    ExtendedPdfSigValResult sigValResult) {
    if (!sigValResult.isCoversDocument()) {
      ValidationStatusType signatureValidationStatus = signatureValidationReportType.getSignatureValidationStatus();
      signatureValidationStatus.addSubIndication(SubIndication.DOCUMENT_PARTIALLY_SIGNED.getUri());
      TypedDataType typedDataType = signatureValidationStatus.addNewAssociatedValidationReportData()
        .addNewAdditionalValidationReportData()
        .addNewReportData();
      XmlString xmlString = XmlString.Factory.newInstance();
      xmlString.setStringValue("Signature does not cover the full document");
      typedDataType.setValue(xmlString);
      typedDataType.setType(SigValIdentifiers.SIG_VALIDATION_REPORT_STATUS_MESSAGE);
    }
  }


  private SignerInfo getSignerInfo(ExtendedPdfSigValResult sigValResult) throws IOException {
    ASN1InputStream asn1Stream = null;
    try {
      asn1Stream = new ASN1InputStream(sigValResult.getSignedData());
      ContentInfo contentInfo = ContentInfo.getInstance(asn1Stream.readObject());
      if (!contentInfo.getContentType().equals(PKCSObjectIdentifiers.signedData)) {
        throw new IOException("Illegal content for PDF signature. Must contain SignedData");
      }
      SignedData signedData = SignedData.getInstance(contentInfo.getContent());
      SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
      return signerInfo;
    }
    catch (Exception ex) {
      throw (ex instanceof IOException) ? (IOException) ex : new IOException(ex);
    }
    finally {
      if (asn1Stream != null) {
        try {
          asn1Stream.close();
        }
        catch (IOException e) {
        }
      }
    }
  }

}
