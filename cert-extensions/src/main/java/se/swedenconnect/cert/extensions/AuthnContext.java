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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * Authentication Context X.509 extension (RFC 7773) implementation for extending Bouncycastle.
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
 * <p>
 * Two context types are supported: SAML Authentication Context Information (SACI, RFC 7773 Section 3) and OpenID
 * Connect Authentication Context Information (OACI, draft-santesson-oidc-cert-auth-context). Entries of any other
 * context type are retained as raw data and otherwise ignored, as required by the processing rules of the latter
 * specification; they are never a reason to reject the extension.
 * </p>
 */
@Slf4j
public class AuthnContext extends ASN1Object {

  /** Extension OID */
  public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.752.201.5.1");

  /** contextType URI for SAML Authentication Context Information (RFC 7773) */
  public static final String SACI_CONTEXT_TYPE = "http://id.elegnamnden.se/auth-cont/1.0/saci";

  /** contextType URI for OpenID Connect Authentication Context Information */
  public static final String OACI_CONTEXT_TYPE = "urn:ietf:params:x509-auth-context:oidc";

  /**
   * contextType URI for SAML Authentication Context Information
   *
   * @deprecated use {@link #SACI_CONTEXT_TYPE}
   */
  @Deprecated
  public static final String CONTENT_TYPE = SACI_CONTEXT_TYPE;

  /** The entries of the extension, in order */
  private final List<AuthnContextEntry> entries;

  /**
   * Creates an instance of the Authentication context extension with strict content validation.
   * <p>
   * Strict mode enforces the content rules of RFC 7773 (for SACI) and of draft-santesson-oidc-cert-auth-context (for
   * OACI). It does not enforce the requirements of any deployment profile. Use {@link #getInstance(Object, boolean)}
   * with {@code strictMode = false} to accept extension content that is well-formed but violates these rules, for
   * example when rendering the content of a certificate for display or reporting.
   * </p>
   *
   * @param obj object holding extension data
   * @return Authentication context extension
   */
  public static AuthnContext getInstance(final Object obj) {
    return getInstance(obj, true);
  }

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param obj object holding extension data
   * @param strictMode strict syntax processing
   * @return Authentication context extension
   */
  public static AuthnContext getInstance(final Object obj, final boolean strictMode) {
    if (obj instanceof AuthnContext) {
      return (AuthnContext) obj;
    }
    if (obj != null) {
      return new AuthnContext(ASN1Sequence.getInstance(obj), strictMode);
    }
    throw new IllegalArgumentException("Invalid object: " + obj);
  }

  /**
   * Creates an instance of the Authentication context extension with strict content validation, see
   * {@link #getInstance(Object)}
   *
   * @param extensions Authentication context extension
   * @return Authentication context extension
   */
  public static AuthnContext fromExtensions(final Extensions extensions) {
    return fromExtensions(extensions, true);
  }

  /**
   * Creates an instance of the Authentication context extension
   *
   * @param extensions Authentication context extension
   * @param strictMode strict syntax processing
   * @return Authentication context extension
   */
  public static AuthnContext fromExtensions(final Extensions extensions, final boolean strictMode) {
    return AuthnContext.getInstance(extensions.getExtensionParsedValue(OID), strictMode);
  }

  /**
   * Internal constructor
   * <p>
   * Parses the content of the ASN.1 sequence. The context type of each entry is examined first; only entries of
   * supported context types are parsed further. Entries of unsupported types are retained as raw data. Malformed
   * content of a supported type is an error regardless of mode; {@code strictMode} additionally enforces the content
   * requirement rules of the respective specification.
   * </p>
   *
   * @param seq ASN1 sequence
   * @param strictMode strict syntax processing
   */
  private AuthnContext(final ASN1Sequence seq, final boolean strictMode) {
    final List<AuthnContextEntry> parsedEntries = new ArrayList<>();
    try {
      for (int i = 0; i < seq.size(); i++) {
        final ASN1Sequence contSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
        final String contextType = ASN1UTF8String.getInstance(contSeq.getObjectAt(0)).getString();
        final String contextInfo = contSeq.size() > 1
          ? ASN1UTF8String.getInstance(contSeq.getObjectAt(1)).getString()
          : null;
        parsedEntries.add(parseEntry(contextType, contextInfo, strictMode));
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Bad extension content", e);
    }
    this.entries = Collections.unmodifiableList(parsedEntries);
  }

  /**
   * Parses one entry according to its context type
   *
   * @param contextType contextType URI
   * @param contextInfo contextInfo string or null
   * @param strictMode strict syntax processing
   * @return the entry
   * @throws IOException on parsing errors of a supported type
   * @throws CertificateException on content validation errors of a supported type
   */
  private static AuthnContextEntry parseEntry(final String contextType, final String contextInfo,
    final boolean strictMode) throws IOException, CertificateException {
    if (SACI_CONTEXT_TYPE.equalsIgnoreCase(contextType)) {
      if (contextInfo == null) {
        throw new CertificateException("Missing contextInfo for SACI entry");
      }
      return new AuthnContextEntry(contextType, contextInfo, getAuthnContext(contextInfo, strictMode));
    }
    if (OACI_CONTEXT_TYPE.equalsIgnoreCase(contextType)) {
      if (contextInfo == null) {
        throw new CertificateException("Missing contextInfo for OACI entry");
      }
      return new AuthnContextEntry(contextType, contextInfo, getOidcAuthnContext(contextInfo, strictMode));
    }
    log.debug("Ignoring Authentication Context entry of unsupported context type {}", contextType);
    return new AuthnContextEntry(contextType, contextInfo);
  }

  /**
   * Internal constructor from entries
   *
   * @param entries entries
   * @param unused disambiguation parameter
   */
  private AuthnContext(final List<AuthnContextEntry> entries, final boolean unused) {
    this.entries = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(entries)));
  }

  /**
   * Constructor for an extension holding SAML Authentication Context Information
   *
   * @param statementInfoList list of SACI data
   */
  public AuthnContext(final List<SAMLAuthContext> statementInfoList) {
    this(statementInfoList.stream().map(AuthnContextEntry::new).collect(Collectors.toList()), true);
  }

  /**
   * Creates an extension from a list of entries of any context types
   *
   * @param entries entries
   * @return Authentication context extension
   */
  public static AuthnContext fromEntries(final List<AuthnContextEntry> entries) {
    return new AuthnContext(entries, true);
  }

  /**
   * Creates an extension holding OpenID Connect Authentication Context Information
   *
   * @param oidcAuthContexts OACI data
   * @return Authentication context extension
   */
  public static AuthnContext fromOidc(final List<OIDCAuthContext> oidcAuthContexts) {
    return fromEntries(oidcAuthContexts.stream().map(AuthnContextEntry::new).collect(Collectors.toList()));
  }

  /**
   * Gets all entries of the extension, including entries of unsupported context types
   *
   * @return unmodifiable list of entries
   */
  public List<AuthnContextEntry> getEntries() {
    return this.entries;
  }

  /**
   * Gets the SAML Authentication Context Information entries
   *
   * @return list of SACI data, empty if none
   */
  public List<SAMLAuthContext> getSamlAuthContexts() {
    return this.entries.stream()
      .filter(AuthnContextEntry::isSaml)
      .map(AuthnContextEntry::getSamlAuthContext)
      .collect(Collectors.toList());
  }

  /**
   * Gets the OpenID Connect Authentication Context Information entries
   *
   * @return list of OACI data, empty if none
   */
  public List<OIDCAuthContext> getOidcAuthContexts() {
    return this.entries.stream()
      .filter(AuthnContextEntry::isOidc)
      .map(AuthnContextEntry::getOidcAuthContext)
      .collect(Collectors.toList());
  }

  /**
   * Gets the SAML Authentication Context Information entries
   *
   * @return list of SACI data, empty if none
   * @deprecated use {@link #getSamlAuthContexts()}
   */
  @Deprecated
  public List<SAMLAuthContext> getStatementInfoList() {
    return this.getSamlAuthContexts();
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   *
   * @return ASN.1 object of the extension
   */
  @Override
  public ASN1Primitive toASN1Primitive() {
    final ASN1EncodableVector authnContexts = new ASN1EncodableVector();

    for (final AuthnContextEntry entry : this.entries) {
      final ASN1EncodableVector authnContext = new ASN1EncodableVector();
      try {
        authnContext.add(new DERUTF8String(entry.getContextType()));
        final String contextInfo = entry.getContextInfo(false);
        if (contextInfo != null) {
          authnContext.add(new DERUTF8String(contextInfo));
        }
        authnContexts.add(new DERSequence(authnContext));
      }
      catch (final Exception ex) {
        log.warn("Unable to encode Authentication Context entry of type {}: {}", entry.getContextType(),
          ex.getMessage());
      }
    }
    return new DERSequence(authnContexts);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder b = new StringBuilder();
    for (final AuthnContextEntry entry : this.entries) {
      if (entry.isSaml()) {
        b.append(" SAML Authentication Context Info (").append(entry.getContextType()).append("):\n");
      }
      else if (entry.isOidc()) {
        b.append(" OpenID Connect Authentication Context Info (").append(entry.getContextType()).append("):\n");
      }
      else {
        b.append(" Unsupported Authentication Context type (").append(entry.getContextType()).append("):\n");
      }
      try {
        final String info = entry.getContextInfo(true);
        b.append(info == null ? "  (no contextInfo)" : info).append("\n");
      }
      catch (final IOException ex) {
        b.append("Bad content: ").append(ex.getMessage()).append("\n");
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
  public static SAMLAuthContext getAuthnContext(final String xml, final boolean strictMode) throws IOException {
    try {
      final Document document = DOMUtils.getDocument(xml.getBytes(StandardCharsets.UTF_8));
      return new SAMLAuthContext(document, strictMode);
    }
    catch (SAXException | ParserConfigurationException | CertificateException e) {
      throw new IOException("Unable to parse SAMLAuthContext xml: " + e.getMessage());
    }
  }

  /**
   * Creates an {@link OIDCAuthContext} object from a JSON string
   *
   * @param json JSON string
   * @param strictMode true to strictly enforce content requirement rules
   * @return {@link OIDCAuthContext} object
   * @throws IOException on error parsing data
   */
  public static OIDCAuthContext getOidcAuthnContext(final String json, final boolean strictMode) throws IOException {
    try {
      return OIDCAuthContext.parse(json, strictMode);
    }
    catch (final CertificateException e) {
      throw new IOException("Unable to parse OIDCAuthContext JSON: " + e.getMessage(), e);
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
      final Document document = authnConext.getDocument();
      document.setXmlStandalone(true);
      if (formatted) {
        return DOMUtils.getStyledDocText(document, false);
      }
      return new String(DOMUtils.getCanonicalDocText(document, false), StandardCharsets.UTF_8);
    }
    catch (final TransformerException e) {
      throw new IOException("Error converting SAMLAuthContext to xml string", e);
    }
  }

  /**
   * Converts an {@link OIDCAuthContext} object to a JSON string
   *
   * @param authnContext {@link OIDCAuthContext} object
   * @param formatted true to generate a pretty printed version, false for the compact form used in certificates
   * @return JSON string
   * @throws IOException on error serializing data
   */
  public static String printAuthnContext(final OIDCAuthContext authnContext, final boolean formatted)
    throws IOException {
    try {
      return authnContext.toJson(formatted);
    }
    catch (final RuntimeException e) {
      throw new IOException("Error converting OIDCAuthContext to JSON string", e);
    }
  }

}
