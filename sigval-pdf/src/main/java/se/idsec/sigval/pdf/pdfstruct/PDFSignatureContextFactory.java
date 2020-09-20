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

import java.io.IOException;

/**
 * Provides a factory that provides an implementation of the PDFSignatureContext interface
 *
 * <p>The PDFSignatureContext interface provides a standard set of functions that can be used to determine
 * the state of a PDF document before and after it was signed such as:</p>
 *
 * <ul>
 *   <li>Extract the version of the document that was signed by a particular signature</li>
 *   <li>Determine if a document has non signature updates applied to the document after the document was signed</li>
 *   <li>Determine if a signature covers the visual content that is shown if the full document is displayed</li>
 * </ul>
 *
 * <p>The logic provided by a PDFSignatureContext implementation can be a moving target and also policy driven.
 * The PDF signature validator needs an implementation of this factory to provide it with a current and relevant version to
 * determine the validity of the signature and whether the signature covers the whole document</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFSignatureContextFactory {

  /**
   * Provide a PDF signature context object for a particular PDF document. This signature context object can be used to determine signature
   * validity and whether a signature in the document covers the whole document.
   * @param pdfDocument the target PDF document
   * @return an implementatioin of the {@link PDFSignatureContext} interface
   * @throws IOException error parsing the provided PDF document
   */
  PDFSignatureContext getPdfSignatureContext(byte[] pdfDocument) throws IOException;

}
