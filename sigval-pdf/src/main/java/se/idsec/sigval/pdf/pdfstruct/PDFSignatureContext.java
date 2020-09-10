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

package se.idsec.sigval.pdf.pdfstruct;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * The PDFSignatureContext interface provides a standard set of functions that can be used to determine
 * the state of a PDF document before and after it was signed such as:
 *
 * <ul>
 *   <li>Extract the version of the document that was signed by a particular signature</li>
 *   <li>Determine if a document has non signature updates applied to the document after the document was signed</li>
 *   <li>Determine if a signature covers the visual content that is shown if the full document is displayed</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFSignatureContext {

  /**
   * Extracts the bytes of the PDF document that was signed by the provided signature
   *
   * @param signature pdf signature
   * @return the byes signed by the provided signature
   * @throws IllegalArgumentException if the signature is not found or no signed data can be located
   */
  byte[] getSignedDocument(PDSignature signature) throws IllegalArgumentException;

  /**
   * Check if the pdf document was updated after this signature was added to the document, where the new update is not
   * a new signature or document timestamp or is a valid DSS store.
   *
   * <p>An update to a PDF document applied after the PDF document was signed invalidates any existing signture unless the
   * update is not a new signature, document timestamp or a DSS store</p>
   *
   * <p>Some validation policies may require that any new signatures or document timestamps must be trusted and verified
   * for it to be an acceptable update to a signed document</p>
   *
   * @param signature the PDF signature
   * @return true if the provided signature was updated by a non signature update
   * @throws IllegalArgumentException on failure to test if the signature was updated by a non signature update
   */
  boolean isSignatureExtendedByNonSignatureUpdates(PDSignature signature) throws IllegalArgumentException;

  /**
   * Test if this signature covers the whole document.
   *
   * <p>Signature is considered to cover the whole document if it is the last update to the PDF document (byte range covers the whole document) or:</p>
   * <ul>
   *   <li>All new updates are signature, doc timestamp or DSS updates, and</li>
   *   <li>Updates to existing objects is limited to the root object, and</li>
   *   <li>Root objects contains no changes but allows added items, and</li>
   *   <li>Where added items to the root object is limited to "DSS" and "AcroForm</li>
   * </ul>
   *
   * @param signature The signature tested if it covers the whole document
   * @return true if the signature covers the whole document
   */
  boolean isCoversWholeDocument(PDSignature signature) throws IllegalArgumentException;

  /**
   * Getter for PDF document revision data
   * @return PDF document revision data for all document revisions
   */
  java.util.List<PDFDocRevision> getPdfDocRevisions();

  /**
   * Getter for PDF signature objects in the examined document. The purpose of this function is that it avoids creating a new
   * load of the document to obtain the signatures in cases where this signature context processor is used.
   * @return signatures
   */
  java.util.List<PDSignature> getSignatures();
}
