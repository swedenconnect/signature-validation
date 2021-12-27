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

package se.swedenconnect.sigval.pdf.verify;

import se.idsec.signservice.security.sign.pdf.PDFSignatureValidator;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;

import java.security.SignatureException;

public interface ExtendedPDFSignatureValidator extends PDFSignatureValidator {

  /**
   * Compile a complete PDF signature verification result object from the list of individual signature results
   *
   * @param pdfDocBytes validate the complete PDF document and return concluding validation results for the complete document.
   * @return PDF signature validation result objects
   * @throws SignatureException errors validating signature
   */
  SignedDocumentValidationResult<ExtendedPdfSigValResult> extendedResultValidation(byte[] pdfDocBytes) throws SignatureException;

}
