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

import java.math.BigDecimal;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.data.ProtocolAuthContext;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * OpenID Connect Authentication Context Information (OACI) as defined in
 * draft-santesson-oidc-cert-auth-context.
 * <p>
 * This is the JSON counterpart of the SAML Authentication Context Information (SACI) defined in RFC 7773. The
 * {@code contextInfo} of an {@code AuthenticationContext} with {@code contextType}
 * {@value AuthnContext#OACI_CONTEXT_TYPE} holds a single JSON object conforming to
 * I-JSON (RFC 7493). Member names and value formats follow the corresponding ID Token claims so that values are copied
 * without conversion.
 * </p>
 * <p>
 * Members not defined by the specification are never rejected when parsing, as required by the specification; they are retained in {@link #getAdditionalMembers()} and re-emitted when serializing. In strict mode the content
 * requirement rules of the specification are enforced; in lenient mode only well-formedness and value types are
 * checked, mirroring the behavior of the SACI implementation. Strict mode enforces the rules of the Internet-Draft
 * only. Requirements imposed by a deployment profile, such as the Sweden Connect certificate profile, are policy and
 * belong in the validation layer, not in this class.
 * </p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OIDCAuthContext implements ProtocolAuthContext {

  /** JSON member name: Issuer Identifier of the OpenID Provider */
  public static final String ISS = "iss";
  /** JSON member name: time of authentication (NumericDate) */
  public static final String AUTH_TIME = "auth_time";
  /** JSON member name: Authentication Context Class Reference */
  public static final String ACR = "acr";
  /** JSON member name: Authentication Methods References */
  public static final String AMR = "amr";
  /** JSON member name: ID Token identifier */
  public static final String JTI = "jti";
  /** JSON member name: Subject Identifier at the OpenID Provider */
  public static final String SUB = "sub";
  /** JSON member name: client identifier of the Relying Party */
  public static final String CLIENT_ID = "client_id";
  /** JSON member name: claim mappings */
  public static final String CLAIM_MAPPINGS = "claim_mappings";

  /** The member names defined by the specification */
  public static final Set<String> DEFINED_MEMBERS = Set.of(ISS, AUTH_TIME, ACR, AMR, JTI, SUB, CLIENT_ID, CLAIM_MAPPINGS);

  /**
   * Mapper used for reading and writing OACI. Duplicate member names are rejected as required by I-JSON.
   */
  private static final JsonMapper MAPPER = JsonMapper.builder()
    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
    .build();

  /** Issuer Identifier of the OpenID Provider ({@code iss}) */
  private String iss;

  /**
   * Time of authentication as a NumericDate ({@code auth_time}): seconds since 1970-01-01T00:00:00Z. Held as a
   * {@link Number} ({@link Long} for integral values, {@link BigDecimal} otherwise) so that the value is written
   * exactly as it was read.
   */
  private Number authTime;

  /** Authentication Context Class Reference ({@code acr}) */
  private String acr;

  /** Authentication Methods References ({@code amr}) */
  private List<String> amr;

  /** Identifier of the ID Token ({@code jti}) */
  private String jti;

  /** Subject Identifier of the End-User at the OpenID Provider ({@code sub}) */
  private String sub;

  /** Client identifier under which the CA, or an RA acting for it, acted as Relying Party ({@code client_id}) */
  private String clientId;

  /** Mappings from End-User claims to certificate subject name attributes ({@code claim_mappings}) */
  private List<ClaimMapping> claimMappings;

  /**
   * Members of the OACI object other than those defined by the specification, in document order. Such members are
   * carried as JSON values so that extensions defined by deployment profiles survive parsing and re-encoding. Names
   * MUST NOT collide with the defined member names.
   */
  private Map<String, JsonNode> additionalMembers;

  /**
   * Parses OACI from its JSON text with strict content validation
   *
   * @param json JSON text
   * @return parsed OACI object
   * @throws CertificateException if the JSON is malformed or violates content rules
   */
  public static OIDCAuthContext parse(final String json) throws CertificateException {
    return parse(json, true);
  }

  /**
   * Parses OACI from its JSON text
   *
   * @param json JSON text
   * @param strictMode true to strictly enforce content requirement rules
   * @return parsed OACI object
   * @throws CertificateException if the JSON is malformed or violates content rules
   */
  public static OIDCAuthContext parse(final String json, final boolean strictMode) throws CertificateException {
    if (json == null) {
      throw new CertificateException("OACI content is missing");
    }
    final JsonNode root;
    try {
      root = MAPPER.readTree(json);
    }
    catch (final JacksonException e) {
      throw new CertificateException("Unable to parse OACI JSON: " + e.getMessage(), e);
    }
    return fromJson(root, strictMode);
  }

  /**
   * Creates an OACI object from a parsed JSON tree with strict content validation
   *
   * @param root the top-level JSON value
   * @return OACI object
   * @throws CertificateException content validation errors
   */
  public static OIDCAuthContext fromJson(final JsonNode root) throws CertificateException {
    return fromJson(root, true);
  }

  /**
   * Creates an OACI object from a parsed JSON tree
   *
   * @param root the top-level JSON value
   * @param strictMode true to strictly enforce content requirement rules
   * @return OACI object
   * @throws CertificateException content validation errors
   */
  public static OIDCAuthContext fromJson(final JsonNode root, final boolean strictMode) throws CertificateException {
    if (root == null || !root.isObject()) {
      throw new CertificateException("OACI content is not a JSON object");
    }
    final OIDCAuthContext oaci = new OIDCAuthContext();
    oaci.iss = getString(root, ISS);
    oaci.authTime = getNumber(root, AUTH_TIME);
    oaci.acr = getString(root, ACR);
    oaci.amr = getStringArray(root, AMR);
    oaci.jti = getString(root, JTI);
    oaci.sub = getString(root, SUB);
    oaci.clientId = getString(root, CLIENT_ID);

    final JsonNode mappingsNode = root.get(CLAIM_MAPPINGS);
    if (mappingsNode != null && !mappingsNode.isNull()) {
      if (!mappingsNode.isArray()) {
        throw new CertificateException("Member " + CLAIM_MAPPINGS + " is not a JSON array");
      }
      final List<ClaimMapping> mappings = new ArrayList<>();
      for (final JsonNode mappingNode : mappingsNode) {
        mappings.add(ClaimMapping.fromJson(mappingNode, strictMode));
      }
      oaci.claimMappings = mappings;
    }
    final Map<String, JsonNode> additional = new LinkedHashMap<>();
    for (final Map.Entry<String, JsonNode> property : root.properties()) {
      if (!DEFINED_MEMBERS.contains(property.getKey())) {
        additional.put(property.getKey(), property.getValue());
      }
    }
    oaci.additionalMembers = additional.isEmpty() ? null : additional;
    oaci.validate(strictMode);
    return oaci;
  }

  /**
   * Validates the content of this object
   *
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation errors
   */
  public void validate(final boolean strictMode) throws CertificateException {
    if (!strictMode) {
      return;
    }
    if (this.iss == null || this.iss.isEmpty()) {
      throw new CertificateException("Member " + ISS + " is required");
    }
    try {
      final URI issUri = new URI(this.iss);
      if (!"https".equals(issUri.getScheme()) || issUri.getQuery() != null || issUri.getFragment() != null) {
        throw new CertificateException("Member " + ISS + " must be an https URL without query or fragment");
      }
    }
    catch (final URISyntaxException e) {
      throw new CertificateException("Member " + ISS + " is not a valid URI", e);
    }
    if (this.authTime != null && this.authTime.doubleValue() < 0) {
      throw new CertificateException("Member " + AUTH_TIME + " must not be negative");
    }
    if (this.acr != null && this.acr.isEmpty()) {
      throw new CertificateException("Member " + ACR + " must not be empty");
    }
    if (this.amr != null && this.amr.isEmpty()) {
      throw new CertificateException("Member " + AMR + " must not be an empty array");
    }
    if (this.claimMappings != null) {
      if (this.claimMappings.isEmpty()) {
        throw new CertificateException("Member " + CLAIM_MAPPINGS + " must not be an empty array");
      }
      for (final ClaimMapping mapping : this.claimMappings) {
        mapping.validate(true);
      }
    }
    if (this.additionalMembers != null) {
      for (final String name : this.additionalMembers.keySet()) {
        if (DEFINED_MEMBERS.contains(name)) {
          throw new CertificateException("Additional member name collides with defined member: " + name);
        }
      }
    }
  }

  /**
   * Serializes this object to JSON text
   *
   * @param formatted true for a pretty-printed form, false for the compact form used in the certificate extension
   * @return JSON text
   */
  /** {@inheritDoc} */
  @Override
  public String getContextType() {
    return AuthnContext.OACI_CONTEXT_TYPE;
  }

  /** {@inheritDoc} */
  @Override
  public String toContextInfo(final boolean formatted) {
    return this.toJson(formatted);
  }

  public String toJson(final boolean formatted) {
    final ObjectNode root = MAPPER.createObjectNode();
    if (this.iss != null) {
      root.put(ISS, this.iss);
    }
    if (this.authTime != null) {
      if (this.authTime instanceof BigDecimal) {
        root.put(AUTH_TIME, (BigDecimal) this.authTime);
      }
      else {
        root.put(AUTH_TIME, this.authTime.longValue());
      }
    }
    if (this.acr != null) {
      root.put(ACR, this.acr);
    }
    if (this.amr != null) {
      final ArrayNode amrNode = root.putArray(AMR);
      this.amr.forEach(amrNode::add);
    }
    if (this.jti != null) {
      root.put(JTI, this.jti);
    }
    if (this.sub != null) {
      root.put(SUB, this.sub);
    }
    if (this.clientId != null) {
      root.put(CLIENT_ID, this.clientId);
    }
    if (this.claimMappings != null) {
      final ArrayNode mappingsNode = root.putArray(CLAIM_MAPPINGS);
      for (final ClaimMapping mapping : this.claimMappings) {
        mapping.toJson(mappingsNode.addObject());
      }
    }
    if (this.additionalMembers != null) {
      for (final Map.Entry<String, JsonNode> member : this.additionalMembers.entrySet()) {
        if (!DEFINED_MEMBERS.contains(member.getKey())) {
          root.set(member.getKey(), member.getValue());
        }
      }
    }
    return formatted
      ? MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root)
      : MAPPER.writeValueAsString(root);
  }

  /**
   * Gets the time of authentication as an {@link Instant}
   *
   * @return the time of authentication, or null if {@code auth_time} is absent
   */
  public Instant getAuthTimeInstant() {
    if (this.authTime == null) {
      return null;
    }
    if (this.authTime instanceof BigDecimal) {
      final BigDecimal decimal = (BigDecimal) this.authTime;
      final long seconds = decimal.longValue();
      final long nanos = decimal.subtract(BigDecimal.valueOf(seconds)).movePointRight(9).longValue();
      return Instant.ofEpochSecond(seconds, nanos);
    }
    return Instant.ofEpochSecond(this.authTime.longValue());
  }

  /**
   * Sets the time of authentication from an {@link Instant}, truncated to whole seconds
   *
   * @param instant the time of authentication
   */
  public void setAuthTimeInstant(final Instant instant) {
    this.authTime = instant == null ? null : instant.getEpochSecond();
  }

  /**
   * Reads an optional string member
   *
   * @param node parent object
   * @param name member name
   * @return the string value, or null if the member is absent or null
   * @throws CertificateException if the member is present but not a string
   */
  static String getString(final JsonNode node, final String name) throws CertificateException {
    final JsonNode value = node.get(name);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isString()) {
      throw new CertificateException("Member " + name + " is not a JSON string");
    }
    return value.asString();
  }

  /**
   * Reads an optional number member
   *
   * @param node parent object
   * @param name member name
   * @return a Long for integral values, a BigDecimal otherwise, or null if absent
   * @throws CertificateException if the member is present but not a number
   */
  static Number getNumber(final JsonNode node, final String name) throws CertificateException {
    final JsonNode value = node.get(name);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isNumber()) {
      throw new CertificateException("Member " + name + " is not a JSON number");
    }
    if (value.isIntegralNumber() && value.canConvertToLong()) {
      return value.longValue();
    }
    return value.decimalValue();
  }

  /**
   * Reads an optional array-of-strings member
   *
   * @param node parent object
   * @param name member name
   * @return the list of strings, or null if the member is absent
   * @throws CertificateException if the member is not an array of strings
   */
  static List<String> getStringArray(final JsonNode node, final String name) throws CertificateException {
    final JsonNode value = node.get(name);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isArray()) {
      throw new CertificateException("Member " + name + " is not a JSON array");
    }
    final List<String> result = new ArrayList<>();
    for (final JsonNode item : value) {
      if (!item.isString()) {
        throw new CertificateException("Member " + name + " contains a value that is not a JSON string");
      }
      result.add(item.asString());
    }
    return result;
  }

}
