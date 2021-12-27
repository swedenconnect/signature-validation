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

package se.swedenconnect.sigval.xml.verify;

import org.w3c.dom.Document;
import se.idsec.signservice.security.sign.xml.XMLSignatureValidator;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.xml.data.ExtendedXmlSigvalResult;

import java.security.SignatureException;

/**
 * Interface for XML document signature validator extending the generic {@link XMLSignatureValidator} interface
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ExtendedXMLSignedDocumentValidator extends XMLSignatureValidator {

  /**
   * Compile a complete XML signature verification result object from the list of individual signature results
   *
   * @param document validate the complete PDF document and return concluding validation results for the complete document.
   * @return XML signature validation result objects
   * @throws SignatureException error validating signed document
   */
  SignedDocumentValidationResult<ExtendedXmlSigvalResult> extendedResultValidation(Document document) throws SignatureException;

}
