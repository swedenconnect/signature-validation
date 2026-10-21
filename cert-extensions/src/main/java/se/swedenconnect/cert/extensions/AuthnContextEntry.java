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

package se.swedenconnect.cert.extensions;

import java.io.IOException;
import java.util.Objects;

import lombok.Getter;
import se.swedenconnect.cert.extensions.data.ProtocolAuthContext;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;

/**
 * One {@code AuthenticationContext} entry of the Authentication Context extension (RFC 7773).
 *
 * <pre>
 * AuthenticationContext ::= SEQUENCE {
 *     contextType     UTF8String,
 *     contextInfo     UTF8String OPTIONAL
 * }
 * </pre>
 * <p>
 * An entry carries the {@code contextType} URI, the raw {@code contextInfo} string as found in the certificate (if the
 * entry was parsed from one), and, for supported context types, the parsed context information object: a
 * {@link SAMLAuthContext} for {@link AuthnContext#SACI_CONTEXT_TYPE} or an {@link OIDCAuthContext} for
 * {@link AuthnContext#OACI_CONTEXT_TYPE}. Entries of unsupported context types are retained with their raw content so
 * that they are ignored, rather than rejected, and survive re-encoding unchanged.
 * </p>
 */
public final class AuthnContextEntry {

  /** The contextType URI */
  @Getter
  private final String contextType;

  /** The raw contextInfo string as parsed from a certificate, or null if constructed from a parsed object */
  @Getter
  private final String rawContextInfo;

  /** The parsed context information for supported types, otherwise null */
  @Getter
  private final ProtocolAuthContext parsed;

  /**
   * Creates an entry for parsed authentication context information of a supported type
   *
   * @param authContext SACI or OACI data
   */
  public AuthnContextEntry(final ProtocolAuthContext authContext) {
    this(Objects.requireNonNull(authContext).getContextType(), null, authContext);
  }

  /**
   * Creates an entry of an arbitrary context type with raw content
   *
   * @param contextType contextType URI
   * @param contextInfo contextInfo string, or null if absent
   */
  public AuthnContextEntry(final String contextType, final String contextInfo) {
    this(contextType, contextInfo, null);
  }

  /**
   * Internal constructor
   *
   * @param contextType contextType URI
   * @param rawContextInfo raw contextInfo string, or null
   * @param parsed parsed context information object, or null
   */
  AuthnContextEntry(final String contextType, final String rawContextInfo, final ProtocolAuthContext parsed) {
    this.contextType = Objects.requireNonNull(contextType, "contextType must not be null");
    this.rawContextInfo = rawContextInfo;
    this.parsed = parsed;
  }

  /**
   * Predicate for SACI entries
   *
   * @return true if this entry holds parsed SAML Authentication Context Information
   */
  public boolean isSaml() {
    return this.parsed instanceof SAMLAuthContext;
  }

  /**
   * Predicate for OACI entries
   *
   * @return true if this entry holds parsed OpenID Connect Authentication Context Information
   */
  public boolean isOidc() {
    return this.parsed instanceof OIDCAuthContext;
  }

  /**
   * Gets the SACI data of this entry
   *
   * @return SACI data, or null if this is not a SACI entry
   */
  public SAMLAuthContext getSamlAuthContext() {
    return this.isSaml() ? (SAMLAuthContext) this.parsed : null;
  }

  /**
   * Gets the OACI data of this entry
   *
   * @return OACI data, or null if this is not an OACI entry
   */
  public OIDCAuthContext getOidcAuthContext() {
    return this.isOidc() ? (OIDCAuthContext) this.parsed : null;
  }

  /**
   * Gets the contextInfo string to encode for this entry.
   * <p>
   * For supported context types the string is produced from the parsed object, so that modifications made to the
   * parsed object after parsing are reflected when re-encoding. For unsupported types the raw string is returned.
   * </p>
   *
   * @param formatted true to produce a human readable form (only used for display, never for encoding)
   * @return contextInfo string, or null if the entry has no contextInfo
   * @throws IOException on error serializing the parsed object
   */
  public String getContextInfo(final boolean formatted) throws IOException {
    return this.parsed != null ? this.parsed.toContextInfo(formatted) : this.rawContextInfo;
  }

}
