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

package se.swedenconnect.cert.extensions.data;

import java.io.IOException;

/**
 * Authentication context information for one authentication protocol, carried as the {@code contextInfo} of an
 * {@code AuthenticationContext} entry in the Authentication Context extension (RFC 7773).
 * <p>
 * Implementations exist for SAML Authentication Context Information (SACI, RFC 7773 Section 3) and OpenID Connect
 * Authentication Context Information (OACI, draft-santesson-oidc-cert-auth-context).
 * </p>
 */
public interface ProtocolAuthContext {

  /**
   * Gets the {@code contextType} URI identifying this kind of authentication context information
   *
   * @return contextType URI
   */
  String getContextType();

  /**
   * Serializes this authentication context information to the string form carried in {@code contextInfo}
   *
   * @param formatted true to produce a human readable form for display; false to produce the compact form used when
   *          encoding the certificate extension
   * @return the contextInfo string
   * @throws IOException on serialization errors
   */
  String toContextInfo(final boolean formatted) throws IOException;

}
