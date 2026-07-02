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
package se.swedenconnect.sigval.testca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPCertificateVerifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Revocation-focused integration tests for the certificate path validator, run against the embedded three-tier test CA
 * whose CRL and OCSP revocation data are served in-memory (no network). Covers positive and revoked outcomes over both
 * CRL and OCSP, plus the {@code noRevAvail} bypass (RFC 9608).
 *
 * <p>Full path validation ({@link StatusCheckingCertificateValidatorImpl}) exercises CRL, which the validator resolves
 * through the injected {@link TestCRLDataLoader}. OCSP is exercised at the {@link OCSPCertificateVerifier} level with the
 * {@link TestOCSPDataLoader}, because the path validator constructs its own OCSP verifier without a data-loader hook.
 */
class RevocationValidationTest {

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair subjectKeyPair;

  @BeforeAll
  static void generateKeyPair() throws Exception {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("P-256"));
    subjectKeyPair = kpg.generateKeyPair();
  }

  // ---- CRL (full path validation) ----

  @Test
  void validCertificate_validatesViaCrl() throws Exception {
    final X509Certificate ee = issueCertificate("CRL Good", false);

    final PathValidationResult result = validator(true).validate(ee, chain(), null);

    final ValidationStatus status = statusFor(result, ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, status.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.CRL, status.getSourceType());
  }

  @Test
  void revokedCertificate_isRejectedViaCrl() throws Exception {
    final X509Certificate ee = issueCertificate("CRL Revoked", false);
    CA.getTestCA().revokeSigningCertificate(ee.getSerialNumber());

    assertThrows(ExtendedCertPathValidatorException.class,
        () -> validator(true).validate(ee, chain(), null));
  }

  // ---- OCSP (verifier level) ----

  @Test
  void validCertificate_isGoodViaOcsp() throws Exception {
    final X509Certificate ee = CA.getTestCA().issueSigningCertificate(subjectKeyPair.getPublic(), "OCSP Good");

    final ValidationStatus status = ocspStatus(ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, status.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.OCSP, status.getSourceType());
  }

  @Test
  void revokedCertificate_isRevokedViaOcsp() throws Exception {
    final X509Certificate ee = CA.getTestCA().issueSigningCertificate(subjectKeyPair.getPublic(), "OCSP Revoked");
    CA.getTestCA().revokeSigningCertificate(ee.getSerialNumber());

    final ValidationStatus status = ocspStatus(ee);
    assertEquals(ValidationStatus.CertificateValidity.REVOKED, status.getValidity());
  }

  // ---- noRevAvail (RFC 9608) ----

  @Test
  void noRevAvailCertificate_acceptedByDefault() throws Exception {
    final X509Certificate ee = issueCertificate("No Revocation", true);

    final PathValidationResult result = validator(true).validate(ee, chain(), null);

    final ValidationStatus status = statusFor(result, ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, status.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.NO_REV_AVAIL, status.getSourceType());
  }

  @Test
  void noRevAvailCertificate_rejectedWhenAcceptanceDisabled() throws Exception {
    final X509Certificate ee = issueCertificate("No Revocation", true);

    assertThrows(ExtendedCertPathValidatorException.class,
        () -> validator(false).validate(ee, chain(), null));
  }

  // ---- helpers ----

  /**
   * Issues an end-entity certificate from the test Issuing CA. OCSP is always omitted so full path validation stays
   * network-free (CRL only). When {@code noRevAvail} is true the certificate carries the noRevAvail extension and omits
   * the CRL distribution point (a one signature certificate).
   */
  private static X509Certificate issueCertificate(final String commonName, final boolean noRevAvail) throws Exception {
    final IssuerCAService issuingCA = CA.getTestCA().getIssuingCA();
    final DefaultCertificateModelBuilder builder = issuingCA.getCertificateModelBuilder(name(commonName),
        subjectKeyPair.getPublic())
        .ocspServiceUrl(null);
    if (noRevAvail) {
      builder.crlDistributionPoints(null);
      builder.noRevAvail(true);
    }
    final CertificateModel model = builder.build();
    return CAUtils.getCert(issuingCA.issueCertificate(model));
  }

  private static ValidationStatus ocspStatus(final X509Certificate ee) throws Exception {
    final OCSPCertificateVerifier verifier =
        new OCSPCertificateVerifier(ee, CA.getTestCA().getIssuingCACertificate());
    verifier.setOcspDataLoader(CA.getTestCA().createOCSPDataLoader());
    verifier.setIncludeNonce(true);
    return verifier.checkValidity();
  }

  private static StatusCheckingCertificateValidatorImpl validator(final boolean acceptNoRevAvail) throws Exception {
    final CRLCache crlCache = new InMemoryCRLCache(0, CA.getTestCA().createCRLDataLoader());
    final StatusCheckingCertificateValidatorImpl validator = new StatusCheckingCertificateValidatorImpl(
        crlCache, null, CA.getTestCA().getRootCACertificate());
    validator.setSingleThreaded(true);
    validator.setAcceptNoRevAvail(acceptNoRevAvail);
    return validator;
  }

  private static List<X509Certificate> chain() throws Exception {
    return List.of(CA.getTestCA().getIssuingCACertificate());
  }

  private static ValidationStatus statusFor(final PathValidationResult result, final X509Certificate cert) {
    return result.getValidationStatusList().stream()
        .filter(s -> s.getCertificate().equals(cert))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No validation status for certificate"));
  }

  private static CertNameModel<?> name(final String commonName) {
    return new ExplicitCertNameModel(List.of(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.O).value("Example Org").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value(commonName).build()));
  }
}
