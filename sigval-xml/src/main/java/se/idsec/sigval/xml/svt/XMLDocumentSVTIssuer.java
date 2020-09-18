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

package se.idsec.sigval.xml.svt;

import lombok.extern.slf4j.Slf4j;

import javax.swing.text.Document;

@Slf4j
public class XMLDocumentSVTIssuer {

  private final XMLSVTSigValClaimsIssuer svtClaimsIssuer;

  public XMLDocumentSVTIssuer(XMLDocumentSVTMethod svtMethod, XMLSVTSigValClaimsIssuer svtClaimsIssuer) {
    this.svtClaimsIssuer = svtClaimsIssuer;
  }

  public byte[] issueSvt(Document document, XMLDocumentSVTMethod svtMethod){
    // TODO traverse the document signatures and issue SVT according to the declared method

    // Return the enhanced XML document
    return null;
  }

}
