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

package se.idsec.sigval.xml.xmlstruct;

import org.w3c.dom.Element;
import se.idsec.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContext;

import java.io.IOException;

/**
 * The XMLSignatureContext interface provides a standard set of functions that can be used to determine
 * the state of a XML document before and after it was signed such as:
 *
 * <ul>
 *   <li>Extract the version of the document that was signed by a particular signature</li>
 *   <li>Determine if a signature covers the whole document</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface XMLSignatureContext {

  /**
   * Extracts the bytes of the XML document that was signed by the provided signature in exactly the form it was hashed and signed
   *
   * @param signature XML signature element
   * @return the bytes signed by the provided signature
   * @throws IOException if the signature is not found or no signed data can be located
   */
  byte[] getSignedDocument(Element signature);

  /**
   * Test if this signature covers the whole document.
   *
   * <p>Signature is considered to cover the whole document if the first reference of the signature refers to the document root (URI="")
   * or refers to an identifier found in the document root</p>
   *
   * @param signature The signature tested if it covers the whole document
   * @return true if the signature covers the whole document
   */
  boolean isCoversWholeDocument(Element signature);

  /**
   * Parse and extract signature data from the signature
   *
   * @param signature The signature element
   * @param registerIdAttr set to true  to force registration of ID or Id attributes in the signed XML document mapping to Reference URI attributes of the signature
   * @return signature data
   * @throws IOException on error parsing the signature and extracting the necessary information
   */
  SignatureData getSignatureData(Element signature, boolean registerIdAttr) throws IOException;

  /**
   * Returns the bytes of the signed document
   * @return bytes of the signed document
   * @throws IOException on error parsing the document content
   */
  byte[] getDocumentBytes() throws IOException;

}
