/*
 * Copyright (c) 2020. Sweden Connect
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

package se.swedenconnect.cert.extensions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extensions;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * AuthnContext X.509 extension implementation for extending Bouncycastle.
 */
@Slf4j
public class AuthnContext extends ASN1Object {

  public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.752.201.5.1");
  public static final String CONTENT_TYPE = "http://id.elegnamnden.se/auth-cont/1.0/saci";

  @Getter
  private List<SAMLAuthContext> statementInfoList = new ArrayList<>();

  private boolean strictMode;

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param obj object holding extension data
   * @return Authentication context extension
   */
  public static AuthnContext getInstance(final Object obj) {
    return getInstance(obj, false);
  }

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param obj object holding extension data
   * @param strictMode strict syntax processing
   * @return Authentication context extension
   */
  public static AuthnContext getInstance(final Object obj, boolean strictMode) {
    if (obj instanceof AuthnContext) {
      return (AuthnContext) obj;
    }
    if (obj != null) {
      return new AuthnContext(ASN1Sequence.getInstance(obj), strictMode);
    }

    return null;
  }

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param extensions Authentication context extension
   * @return Authentication context extension
   */
  public static AuthnContext fromExtensions(final Extensions extensions) {
    return fromExtensions(extensions, false);
  }

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param extensions Authentication context extension
   * @param strictMode strict syntax processing
   * @return Authentication context extension
   */
  public static AuthnContext fromExtensions(final Extensions extensions, boolean strictMode) {
    return AuthnContext.getInstance(extensions.getExtensionParsedValue(OID), strictMode);
  }

  /**
   * Internal constructor
   * <p>
   * Parse the content of ASN1 sequence to populate set values
   *
   * @param seq ASN1 sequence
   */
  private AuthnContext(final ASN1Sequence seq, boolean strictMode) {
    this.strictMode = strictMode;
    this.statementInfoList = new ArrayList<>();
    try {
      for (int i = 0; i < seq.size(); i++) {
        final ASN1Sequence contSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
        final ASN1UTF8String contextType = ASN1UTF8String.getInstance(contSeq.getObjectAt(0));
        final ASN1UTF8String contextInfo = ASN1UTF8String.getInstance(contSeq.getObjectAt(1));
        final SAMLAuthContext samlAuthContext = getAuthnContext(contextInfo.getString(), strictMode);
        if (contextType.getString().equalsIgnoreCase(CONTENT_TYPE)) {
          this.statementInfoList.add(samlAuthContext);
        }
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Bad extension content", e);
    }
  }

  /**
   * Constructor
   *
   * @param statementInfoList list of statement infos
   */
  public AuthnContext(final List<SAMLAuthContext> statementInfoList) {
    this.statementInfoList = statementInfoList;
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   *
   * <pre>
   * AuthenticationContexts ::= SEQUENCE SIZE (1..MAX) OF
   *                            AuthenticationContext
   *
   * AuthenticationContext ::= SEQUENCE {
   *     contextType     UTF8String,
   *     contextInfo     UTF8String OPTIONAL
   * }
   * </pre>
   *
   * @return ASN.1 object of the extension
   */
  @Override
  public ASN1Primitive toASN1Primitive() {
    final ASN1EncodableVector authnConexts = new ASN1EncodableVector();

    for (final SAMLAuthContext statementInfo : this.statementInfoList) {
      final ASN1EncodableVector authnConext = new ASN1EncodableVector();
      try {
        authnConext.add(new DERUTF8String(CONTENT_TYPE));
        final String contextXML = printAuthnContext(statementInfo, false);
        authnConext.add(new DERUTF8String(contextXML));
        authnConexts.add(new DERSequence(authnConext));
      }
      catch (final Exception ex) {
        Logger.getLogger(AuthnContext.class.getName()).warning(ex.getMessage());
      }
    }
    return new DERSequence(authnConexts);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder b = new StringBuilder();
    // b.append("AuthenticationContext [\n");
    for (final SAMLAuthContext statementInfo : this.statementInfoList) {
      b.append(" SAML Authentication Context Info (http://id.elegnamnden.se/auth-cont/1.0/saci):\n");
      try {
        b.append(printAuthnContext(statementInfo, true)).append("\n");
      }
      catch (final IOException ex) {
        b.append("Bad XML content: ").append(ex.getMessage()).append("\n");
      }
    }
    return b.toString();
  }

  /**
   * Creates a {@link SAMLAuthContext} object from an xml string
   *
   * @param xml xml string
   * @param strictMode true to strictly enforce content requirement rules
   * @return {@link SAMLAuthContext} object
   * @throws IOException on error parsing data
   */
  public static SAMLAuthContext getAuthnContext(final String xml, boolean strictMode) throws IOException {

    try {
      Document document = DOMUtils.getDocument(xml.getBytes(StandardCharsets.UTF_8));
      return new SAMLAuthContext(document, strictMode);
    }
    catch (SAXException | ParserConfigurationException | CertificateException e) {
      throw new IOException("Unable to parse SAMLAuthContext xml: " + e.getMessage());
    }
  }

  /**
   * Converts a {@link SAMLAuthContext} object to XML string
   *
   * @param authnConext {@link SAMLAuthContext} object
   * @param formatted true to generate pretty printing version
   * @return XML string
   * @throws IOException on error parsing data
   */
  public static String printAuthnContext(final SAMLAuthContext authnConext, final boolean formatted)
    throws IOException {

    try {
      Document document = authnConext.getDocument();
      document.setXmlStandalone(true);
      if (formatted) {
        return DOMUtils.getStyledDocText(document, false);
      }
      return new String(DOMUtils.getCanonicalDocText(document, false), StandardCharsets.UTF_8);
    }
    catch (TransformerException e) {
      throw new IOException("Error converting SAMLAuthContext to xml string", e);
    }

  }

}
