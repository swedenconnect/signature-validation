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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Certificate path / trust-anchor integration tests against the embedded three-tier test CA
 * (Root CA -&gt; Issuing CA -&gt; end-entity). Covers a full path to a trusted root, direct trust of intermediate and
 * end-entity certificates, and rejection when the path cannot be built to a trusted anchor.
 */
class CertPathValidationTest {

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair subjectKeyPair;

  @BeforeAll
  static void generateKeyPair() throws Exception {
    subjectKeyPair = generateEcKeyPair();
  }

  @Test
  void validPathToTrustedRoot_succeeds() throws Exception {
    final X509Certificate ee = issueEndEntity("Path To Root");

    final PathValidationResult result = validator(CA.getTestCA().getRootCACertificate())
        .validate(ee, List.of(CA.getTestCA().getIssuingCACertificate()), null);

    // Full chain: end-entity -> issuing CA -> root.
    assertEquals(3, result.getValidatedCertificatePath().size());
    assertEquals(ValidationStatus.CertificateValidity.VALID, statusFor(result, ee).getValidity());
  }

  @Test
  void directTrustOfIntermediate_succeeds() throws Exception {
    final X509Certificate ee = issueEndEntity("Direct Intermediate Trust");

    // Trust the issuing CA directly - the path terminates one step earlier.
    final PathValidationResult result = validator(CA.getTestCA().getIssuingCACertificate())
        .validate(ee, List.of(), null);

    assertEquals(2, result.getValidatedCertificatePath().size());
    assertEquals(ValidationStatus.CertificateValidity.VALID, statusFor(result, ee).getValidity());
  }

  @Test
  void directTrustOfEndEntity_succeeds() throws Exception {
    final X509Certificate ee = issueEndEntity("Direct End Entity Trust");

    // The target certificate is itself a trust anchor - accepted without revocation checking.
    final PathValidationResult result = validator(ee).validate(ee, List.of(), null);

    assertEquals(1, result.getValidatedCertificatePath().size());
    final ValidationStatus status = statusFor(result, ee);
    assertEquals(ValidationStatus.CertificateValidity.VALID, status.getValidity());
    assertEquals(ValidationStatus.ValidatorSourceType.SELF_SIGNED, status.getSourceType());
  }

  @Test
  void unknownRoot_pathBuildingFails() throws Exception {
    final X509Certificate ee = issueEndEntity("Untrusted Root");
    final X509Certificate untrustedAnchor = selfSignedCa("CN=Untrusted Root CA");

    // The end-entity does not chain to the provided (unrelated) trust anchor - path building must fail.
    assertThrows(GeneralSecurityException.class,
        () -> validator(untrustedAnchor)
            .validate(ee, List.of(CA.getTestCA().getIssuingCACertificate()), null));
  }

  // ---- helpers ----

  /** Issues an end-entity certificate with a CRL distribution point but no OCSP (keeps validation network-free). */
  private static X509Certificate issueEndEntity(final String commonName) throws Exception {
    final IssuerCAService issuingCA = CA.getTestCA().getIssuingCA();
    final DefaultCertificateModelBuilder builder = issuingCA.getCertificateModelBuilder(name(commonName),
        subjectKeyPair.getPublic())
        .ocspServiceUrl(null);
    return CAUtils.getCert(issuingCA.issueCertificate(builder.build()));
  }

  private static StatusCheckingCertificateValidatorImpl validator(final X509Certificate... trustAnchors)
      throws Exception {
    final CRLCache crlCache = new InMemoryCRLCache(0, CA.getTestCA().createCRLDataLoader());
    final StatusCheckingCertificateValidatorImpl validator =
        new StatusCheckingCertificateValidatorImpl(crlCache, null, trustAnchors);
    validator.setSingleThreaded(true);
    return validator;
  }

  private static ValidationStatus statusFor(final PathValidationResult result, final X509Certificate cert) {
    return result.getValidationStatusList().stream()
        .filter(s -> s.getCertificate().equals(cert))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No validation status for certificate"));
  }

  /** A self-signed CA certificate that is unrelated to the test CA hierarchy, used as an unknown trust anchor. */
  private static X509Certificate selfSignedCa(final String dn) throws Exception {
    final KeyPair kp = generateEcKeyPair();
    final X500Name name = new X500Name(dn);
    final Date notBefore = Date.from(Instant.now().minusSeconds(3600));
    final Date notAfter = Date.from(Instant.now().plusSeconds(3650L * 24 * 3600));
    final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        name, BigInteger.valueOf(1), notBefore, notAfter, name, kp.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    final ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
        .build(kp.getPrivate());
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
  }

  private static KeyPair generateEcKeyPair() throws Exception {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("P-256"));
    return kpg.generateKeyPair();
  }

  private static CertNameModel<?> name(final String commonName) {
    return new ExplicitCertNameModel(List.of(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.O).value("Example Org").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value(commonName).build()));
  }
}
