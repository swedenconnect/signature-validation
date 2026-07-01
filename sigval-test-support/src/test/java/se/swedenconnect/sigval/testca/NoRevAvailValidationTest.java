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

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.Extension;

import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.GenericExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Validates the noRevAvail handling of {@link StatusCheckingCertificateValidatorImpl} against the embedded test CA,
 * whose CRL revocation data is served in-memory through {@link TestCRLDataLoader}. Because the CA has a working
 * revocation service, the control cases are real: a normal certificate is genuinely CRL-checked and a revoked one is
 * rejected, so the noRevAvail bypass is demonstrated against a live revocation backdrop rather than an empty cache.
 */
class NoRevAvailValidationTest {

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair subjectKeyPair;

  @BeforeAll
  static void generateKeyPair() throws Exception {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("P-256"));
    subjectKeyPair = kpg.generateKeyPair();
  }

  @Test
  void oneSignatureCertificate_acceptedByDefault() throws Exception {
    final X509Certificate ee = issueCertificate("John Doe", true);

    final PathValidationResult result = validator(true).validate(ee, chain(), null);

    final ValidationStatus eeStatus = statusFor(result, ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, eeStatus.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.NO_REV_AVAIL, eeStatus.getSourceType(),
        "acceptance must be recorded as NO_REV_AVAIL, not a positive revocation check");
  }

  @Test
  void oneSignatureCertificate_rejectedWhenAcceptanceDisabled() throws Exception {
    final X509Certificate ee = issueCertificate("John Doe", true);

    // No CRL/OCSP source and acceptance disabled -> validity UNKNOWN -> path validation fails.
    assertThrows(ExtendedCertPathValidatorException.class,
        () -> validator(false).validate(ee, chain(), null));
  }

  @Test
  void normalCertificate_validatesViaCrl() throws Exception {
    final X509Certificate ee = issueCertificate("Regular Signer", false);

    final PathValidationResult result = validator(true).validate(ee, chain(), null);

    final ValidationStatus eeStatus = statusFor(result, ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, eeStatus.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.CRL, eeStatus.getSourceType(),
        "a certificate without noRevAvail must be checked against the CRL");
  }

  @Test
  void revokedCertificate_isRejected() throws Exception {
    final X509Certificate ee = issueCertificate("Revoked Signer", false);
    CA.getTestCA().revokeSigningCertificate(ee.getSerialNumber());

    // The CA genuinely revokes, so a non-noRevAvail certificate must fail - proving the bypass is a real bypass.
    assertThrows(ExtendedCertPathValidatorException.class,
        () -> validator(true).validate(ee, chain(), null));
  }

  // ---- helpers ----

  /**
   * Issues an end-entity certificate from the test Issuing CA. When {@code noRevAvail} is true the certificate carries
   * the noRevAvail extension and omits any revocation source (a one signature certificate); otherwise it keeps the
   * CA's CRL distribution point. OCSP is omitted throughout so the test stays free of network calls.
   */
  private static X509Certificate issueCertificate(final String commonName, final boolean noRevAvail) throws Exception {
    final IssuerCAService issuingCA = CA.getTestCA().getIssuingCA();
    final DefaultCertificateModelBuilder builder = issuingCA.getCertificateModelBuilder(name(commonName),
        subjectKeyPair.getPublic())
        .ocspServiceUrl(null); // keep the test hermetic - revocation is exercised via the in-memory CRL
    if (noRevAvail) {
      builder.crlDistributionPoints(null);
      builder.noRevAvail(true);
    }
    final CertificateModel model = builder.build();
    return CAUtils.getCert(issuingCA.issueCertificate(model));
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
