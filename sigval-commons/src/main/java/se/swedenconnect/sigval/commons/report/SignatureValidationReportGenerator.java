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

package se.swedenconnect.sigval.commons.report;

import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;

/**
 * Generic interface for a signature validation report generator
 *
 * @param <R> The report object
 * @param <T> Signature validation result data
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignatureValidationReportGenerator<R extends Object, T extends ExtendedSigValResult> {

  /**
   * Generate signature validation report
   * @param signatureValidationResult results from signature validation
   * @param documentName optional document name that should be used in the report
   * @param mimeType Mime type of the signed document data
   * @return signature validation report
   */
  R generateSignatureValidationReport(final T signatureValidationResult, final String documentName, final String mimeType);
}
