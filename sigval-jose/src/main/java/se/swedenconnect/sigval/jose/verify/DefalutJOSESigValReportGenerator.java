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

package se.swedenconnect.sigval.jose.verify;

import org.etsi.uri.x01903.v13.DigestAlgAndValueType;
import org.etsi.uri.x19102.v12.SADataObjectFormatType;
import org.etsi.uri.x19102.v12.SignatureValidationProcessType;
import org.etsi.uri.x19102.v12.SignatureValidationReportType;
import org.w3.x2000.x09.xmldsig.DigestMethodType;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.report.impl.AbstractSigValReportGenerator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * XML implementation of the Signature validation report generator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefalutJOSESigValReportGenerator extends AbstractSigValReportGenerator<ExtendedJOSESigvalResult> {

  public DefalutJOSESigValReportGenerator() {
    super(DigestAlgorithm.ID_SHA256);
  }

  public DefalutJOSESigValReportGenerator(String defaultHashAlgo) {
    super(defaultHashAlgo);
  }

  /**
   * Get signature quality from the signature validation result
   *
   * @param sigValResult The result of signature validation
   * @return signature quality
   */
  @Override protected String getSignatureQuality(ExtendedJOSESigvalResult sigValResult) {
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
  @Override protected SignatureValidationProcessType getSignatureValidationProcess(ExtendedJOSESigvalResult sigValResult, String pol) {
    return defaultGetSignatureValidationProcess(sigValResult, pol);
  }

  /**
   * Get the signed data object format for this signature validation result
   *
   * @return Signed data object format
   */
  @Override protected SADataObjectFormatType getDataObjectFormat() {
    SADataObjectFormatType saDataObjectFormatType = SADataObjectFormatType.Factory.newInstance();
    saDataObjectFormatType.setMimeType("application/json");
    return saDataObjectFormatType;
  }

  /**
   * Get the DTBSR (Data to be signed representation) hash value and hash algorithm according the document profile
   *
   * @param sigValResult signature validation result
   * @param hashAlgoId   hash algorithm id
   * @return digest value and algorithm for the DTBSR
   */
  @Override protected DigestAlgAndValueType getSignatureDtbsDigestAndValue(ExtendedJOSESigvalResult sigValResult, String hashAlgoId)
    throws IOException {

    try {
      final String tbsString = sigValResult.getHeader().toBase64URL().toString() + "." + sigValResult.getPayload().toBase64URL().toString();
      byte[] tbsbytes = tbsString.getBytes(StandardCharsets.UTF_8);
      byte[] dtbsrHash = DigestAlgorithmRegistry.get(hashAlgoId).getInstance().digest(tbsbytes);
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
   * @return signature value
   */
  @Override protected byte[] getSignatureValue(ExtendedJOSESigvalResult sigValResult) throws IOException {
    return sigValResult.getSignatureValue();
  }

  /**
   * Apply the final validation checks against any policy provided by the profile
   *
   * @param signatureValidationReportType signature validation report data before policy check
   * @param sigValResult                  signature validation result
   */
  @Override protected void applyValidationPolicy(SignatureValidationReportType signatureValidationReportType,
    ExtendedJOSESigvalResult sigValResult) {
  }
}
