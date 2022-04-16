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

package se.swedenconnect.sigval.report;

import org.etsi.uri.x19102.v12.ValidationReportDocument;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.report.data.SigvalReportOptions;
import se.swedenconnect.sigval.report.xml.ReportSigner;

import java.io.IOException;

/**
 * Interface for creating a signature validation report based on ETSI TS 119 102-2
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SigValReportGenerator<R extends ExtendedSigValResult> {

  /**
   * Provide a signature validation report based on ETSI TS 119 102-2
   * @param validationResult the result of signature validation used to generate the report
   * @param sigvalReportOptions options for building the validation report
   * @param requestID an optional requestID to be included in the report
   * @return signature validation report
   */
  ValidationReportDocument getValidationReport(SignedDocumentValidationResult<R> validationResult,
    SigvalReportOptions sigvalReportOptions, String requestID);

  /**
   * Provide a signed signature validation report based on ETSI TS 119 102-2
   * @param validationResult the result of signature validation used to generate the report
   * @param sigvalReportOptions options for building the validation report
   * @param requestID an optional requestID to be included in the report
   * @return signed signature validation report
   */
  byte[] getSignedValidationReport(SignedDocumentValidationResult<R> validationResult,
    SigvalReportOptions sigvalReportOptions, String requestID, ReportSigner signer) throws IOException;
}
