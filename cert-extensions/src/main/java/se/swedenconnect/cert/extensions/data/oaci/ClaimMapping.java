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

package se.swedenconnect.cert.extensions.data.oaci;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.regex.Pattern;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * A claim mapping object of OpenID Connect Authentication Context Information (OACI).
 * <p>
 * A claim mapping records that the value of a certificate subject name attribute was derived from an End-User claim
 * obtained from the ID Token or the UserInfo Response. The {@code type} and {@code ref} members follow the same rules
 * as the {@code Type} and {@code Ref} attributes of the SAML Authentication Context Information defined in RFC 7773,
 * and the {@link AttributeMapping.Type} enumeration is therefore reused.
 * </p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimMapping {

  /** JSON member name for the mapping type */
  public static final String TYPE = "type";
  /** JSON member name for the certificate attribute reference */
  public static final String REF = "ref";
  /** JSON member name for the claim reference (JSON Pointer) */
  public static final String CLAIM = "claim";
  /** JSON member name for the claim source */
  public static final String SOURCE = "source";

  /** Pattern for an object identifier or SubjectAltName tag number in dotted decimal notation */
  private static final Pattern REF_PATTERN = Pattern.compile("^[0-9]+(\\.[0-9]+)*$");

  /** The type of certificate attribute or name form the claim was mapped to (rdn, san or sda) */
  private AttributeMapping.Type type;

  /** Reference to the certificate attribute: an OID in dotted decimal notation, or a SubjectAltName tag number */
  private String ref;

  /** JSON Pointer (RFC 6901) identifying the claim within the claims set */
  private String claim;

  /** Where the claim was obtained. {@code null} means the default {@link Source#id_token} */
  private Source source;

  /**
   * Enumeration of claim sources
   */
  public enum Source {
    /** The claim was obtained from the ID Token */
    id_token,
    /** The claim was obtained from the UserInfo Response */
    userinfo;

    /**
     * Get the source matching a JSON value
     *
     * @param name JSON value
     * @return the matching Source, or null if no source matches
     */
    public static Source getSourceFromName(final String name) {
      return Arrays.stream(values())
        .filter(source -> source.name().equals(name))
        .findFirst().orElse(null);
    }
  }

  /**
   * Creates a claim mapping from its JSON object representation with strict content validation
   *
   * @param node JSON object
   * @return claim mapping
   * @throws CertificateException content validation errors
   */
  public static ClaimMapping fromJson(final JsonNode node) throws CertificateException {
    return fromJson(node, true);
  }

  /**
   * Creates a claim mapping from its JSON object representation
   *
   * @param node JSON object
   * @param strictMode true to strictly enforce content requirement rules
   * @return claim mapping
   * @throws CertificateException content validation errors
   */
  public static ClaimMapping fromJson(final JsonNode node, final boolean strictMode) throws CertificateException {
    if (node == null || !node.isObject()) {
      throw new CertificateException("Claim mapping is not a JSON object");
    }
    final ClaimMapping mapping = new ClaimMapping();

    final String typeName = OIDCAuthContext.getString(node, TYPE);
    if (typeName != null) {
      mapping.type = AttributeMapping.Type.getTypeFromName(typeName);
      if (mapping.type == null) {
        throw new CertificateException("Illegal claim mapping type: " + typeName);
      }
    }
    mapping.ref = OIDCAuthContext.getString(node, REF);
    mapping.claim = OIDCAuthContext.getString(node, CLAIM);

    final String sourceName = OIDCAuthContext.getString(node, SOURCE);
    if (sourceName != null) {
      mapping.source = Source.getSourceFromName(sourceName);
      if (mapping.source == null) {
        throw new CertificateException("Illegal claim source: " + sourceName);
      }
    }
    mapping.validate(strictMode);
    return mapping;
  }

  /**
   * Validates the content of this claim mapping
   *
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation errors
   */
  public void validate(final boolean strictMode) throws CertificateException {
    if (!strictMode) {
      return;
    }
    if (this.type == null) {
      throw new CertificateException("Claim mapping type is required");
    }
    if (this.ref == null || !REF_PATTERN.matcher(this.ref).matches()) {
      throw new CertificateException("Claim mapping ref must be an OID or tag number in dotted decimal notation");
    }
    if (this.claim == null || this.claim.isEmpty() || !this.claim.startsWith("/")) {
      throw new CertificateException("Claim mapping claim must be a non-empty JSON Pointer");
    }
  }

  /**
   * Writes this claim mapping into a JSON object node
   *
   * @param node the object node to populate
   * @return the populated object node
   */
  public ObjectNode toJson(final ObjectNode node) {
    if (this.type != null) {
      node.put(TYPE, this.type.name());
    }
    if (this.ref != null) {
      node.put(REF, this.ref);
    }
    if (this.claim != null) {
      node.put(CLAIM, this.claim);
    }
    if (this.source != null) {
      node.put(SOURCE, this.source.name());
    }
    return node;
  }

  /**
   * Gets the effective source of the claim, applying the default when no source is set
   *
   * @return the claim source
   */
  public Source getEffectiveSource() {
    return this.source == null ? Source.id_token : this.source;
  }

}
