/*
 * Copyright (c) 2026. Sweden Connect
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
package se.swedenconnect.sigval.xml.xmlstruct;

import org.apache.xml.security.Init;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import se.swedenconnect.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContext;

import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Regression test for the XML signature-wrapping "null id" coverage bypass.
 *
 * <p>The fixture {@code xml-null-id-live-forged-wrapped.xml} is a genuinely signed {@code <SignedRecord Id="null">}
 * whose enveloped signature references {@code URI="#null"}, relocated below a new attacker-controlled
 * {@code <ForgedApplication>} root that carries no id attribute. The forged top-level values are APPROVED / Attacker
 * Controlled / 9000000.00 while the genuine signed values remain DENIED / Original Applicant / 100.00.</p>
 *
 * <p>Because the wrapping root has no id, {@code rootIdAttrVal} is {@code null}, and the previous coverage predicate
 * computed {@code "#" + null == "#null"}, which collided with the signature's genuine {@code #null} reference and
 * wrongly reported whole-document coverage. This test asserts the fixed behaviour: the signature does NOT cover the
 * whole document. It is a structural (trust-free) coverage check, so no trust anchors are required.</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class XmlCoverageRegressionTest {

  /** The XML Signature namespace. */
  private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

  @BeforeAll
  static void init() {
    // Apache Santuario must be initialized before any XMLSignature use.
    if (!Init.isInitialized()) {
      Init.init();
    }
  }

  @Test
  void wrappedSignatureWithNullId_doesNotCoverWholeDocument() throws Exception {
    final Document document = parse(readFixture("/xml-null-id-live-forged-wrapped.xml"));
    final DefaultXMLSignatureContext context = new DefaultXMLSignatureContext(document);

    final Element signatureElement =
        (Element) document.getElementsByTagNameNS(XMLDSIG_NS, "Signature").item(0);
    assertNotNull(signatureElement, "the fixture must contain an XML signature");

    final SignatureData signatureData = context.getSignatureData(signatureElement);
    assertFalse(signatureData.isCoversWholeDoc(),
        "a signature that references a nested Id=\"null\" element, wrapped below an id-less root, must NOT be reported "
            + "as covering the whole document - the '#' + null coverage collision must be rejected");
  }

  private static Document parse(final byte[] xml) throws Exception {
    final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
  }

  private static byte[] readFixture(final String resource) throws Exception {
    try (InputStream is = XmlCoverageRegressionTest.class.getResourceAsStream(resource)) {
      assertNotNull(is, "Test fixture not found on classpath: " + resource);
      return is.readAllBytes();
    }
  }
}
