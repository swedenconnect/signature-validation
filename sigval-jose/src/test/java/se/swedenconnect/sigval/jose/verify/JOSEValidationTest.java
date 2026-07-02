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
package se.swedenconnect.sigval.jose.verify;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;

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

import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;
import se.swedenconnect.sigval.commons.svt.SVTExtendpolicy;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.policy.impl.PkixJOSESignaturePolicyValidator;
import se.swedenconnect.sigval.jose.svt.JOSEDocumentSVTIssuer;
import se.swedenconnect.sigval.jose.svt.JOSESVTSigValClaimsIssuer;
import se.swedenconnect.sigval.jose.svt.JOSESVTValidator;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.testca.SigValTestExtension;

import java.math.BigInteger;
import java.time.Duration;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end JOSE (JWS) signature validation tests. A compact JWS is signed at test time with a certificate issued by
 * the embedded test CA, then validated through {@link JOSESignedDocumentValidator} wired to a certificate validator
 * backed by the CA's in-memory CRL. Covers a trusted, valid signature and an untrusted (self-signed) signer.
 */
class JOSEValidationTest {

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair signerKeyPair;

  @BeforeAll
  static void init() throws Exception {
    signerKeyPair = ecKeyPair();
  }

  @Test
  void validSignature_isTrustedAndValid() throws Exception {
    final X509Certificate signerCert = issueEndEntity("JOSE Signer", signerKeyPair.getPublic());
    final byte[] jws = signJws("Signed JOSE payload", signerKeyPair.getPrivate(),
        List.of(signerCert, CA.getTestCA().getIssuingCACertificate()));

    final ExtendedJOSESigvalResult result = validateFirst(jws);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
  }

  @Test
  void untrustedSigner_isRejected() throws Exception {
    final KeyPair kp = ecKeyPair();
    final X509Certificate selfSigned = selfSigned(kp, "CN=Untrusted JOSE Signer");
    final byte[] jws = signJws("Signed JOSE payload", kp.getPrivate(), List.of(selfSigned));

    final ExtendedJOSESigvalResult result = validateFirst(jws);

    assertEquals(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, result.getStatus());
  }

  @Test
  void svtRoundTrip_validatesViaSvt() throws Exception {
    // 1. A trusted, valid JWS.
    final X509Certificate signerCert = issueEndEntity("SVT Doc Signer", signerKeyPair.getPublic());
    final byte[] jws = signJws("Signed JOSE payload", signerKeyPair.getPrivate(),
        List.of(signerCert, CA.getTestCA().getIssuingCACertificate()));

    // 2. Issue an SVT over it, signed by a separate credential issued by the test CA.
    final KeyPair svtKeyPair = ecKeyPair();
    final X509Certificate svtCert = issueEndEntity("SVT Issuer", svtKeyPair.getPublic());
    final JOSESignatureDataValidatorImpl plainValidator = new JOSESignatureDataValidatorImpl(
        certificateValidator(), new PkixJOSESignaturePolicyValidator(false), null);
    final JOSESVTSigValClaimsIssuer claimsIssuer = new JOSESVTSigValClaimsIssuer(
        JWSAlgorithm.ES256, svtKeyPair.getPrivate(),
        List.of(svtCert, CA.getTestCA().getIssuingCACertificate()), plainValidator);
    final JOSEDocumentSVTIssuer svtIssuer = new JOSEDocumentSVTIssuer(claimsIssuer);
    final SVTModel svtModel = SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .certRef(true)
        .validityPeriod(Duration.ofDays(365).toMillis())
        .build();
    final byte[] svtDocument = svtIssuer.issueSvt(jws, svtModel, SVTExtendpolicy.REPLACE, false);

    // 3. Validate the SVT-extended document; the result must be produced via the SVT path.
    final JOSESVTValidator svtValidator = new JOSESVTValidator(certificateValidator(),
        List.of(svtCert, CA.getTestCA().getIssuingCACertificate()));
    final JOSESignatureDataValidatorImpl svtAwareValidator = new JOSESignatureDataValidatorImpl(
        certificateValidator(), new PkixJOSESignaturePolicyValidator(false), null, svtValidator);
    final List<SignatureValidationResult> results =
        new JOSESignedDocumentValidator(svtAwareValidator).validate(svtDocument, null);
    final ExtendedJOSESigvalResult result = (ExtendedJOSESigvalResult) results.get(0);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
    assertNotNull(result.getSvtJWT(), "result must be produced via the SVT validation path");
  }

  // ---- helpers ----

  private ExtendedJOSESigvalResult validateFirst(final byte[] jws) throws Exception {
    final JOSESignatureDataValidatorImpl dataValidator = new JOSESignatureDataValidatorImpl(
        certificateValidator(), new PkixJOSESignaturePolicyValidator(false), null);
    final JOSESignedDocumentValidator validator = new JOSESignedDocumentValidator(dataValidator);
    final List<SignatureValidationResult> results = validator.validate(jws, null);
    return (ExtendedJOSESigvalResult) results.get(0);
  }

  private CertificateValidator certificateValidator() throws Exception {
    final CRLCache crlCache = new InMemoryCRLCache(0, CA.getTestCA().createCRLDataLoader());
    final StatusCheckingCertificateValidatorImpl validator = new StatusCheckingCertificateValidatorImpl(
        crlCache, null, CA.getTestCA().getRootCACertificate());
    validator.setSingleThreaded(true);
    return validator;
  }

  /** Signs a compact JWS (ES256) placing the given certificate chain in the {@code x5c} header. */
  private static byte[] signJws(final String payload, final PrivateKey signingKey, final List<X509Certificate> x5c)
      throws Exception {
    final List<com.nimbusds.jose.util.Base64> chain = new java.util.ArrayList<>();
    for (final X509Certificate c : x5c) {
      chain.add(com.nimbusds.jose.util.Base64.encode(c.getEncoded()));
    }
    final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).x509CertChain(chain).build();
    final JWSObject jws = new JWSObject(header, new Payload(payload));
    jws.sign(new ECDSASigner((ECPrivateKey) signingKey));
    return jws.serialize().getBytes(java.nio.charset.StandardCharsets.UTF_8);
  }

  /** Issues an end-entity certificate with a CRL distribution point but no OCSP (keeps validation network-free). */
  private static X509Certificate issueEndEntity(final String commonName, final PublicKey publicKey) throws Exception {
    final DefaultCertificateModelBuilder builder = CA.getTestCA().getIssuingCA()
        .getCertificateModelBuilder(name(commonName), publicKey)
        .ocspServiceUrl(null);
    return CAUtils.getCert(CA.getTestCA().getIssuingCA().issueCertificate(builder.build()));
  }

  private static X509Certificate selfSigned(final KeyPair kp, final String dn) throws Exception {
    final X500Name name = new X500Name(dn);
    final Date notBefore = Date.from(Instant.now().minusSeconds(3600));
    final Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
    final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        name, BigInteger.valueOf(1), notBefore, notAfter, name, kp.getPublic());
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
    final ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
        .build(kp.getPrivate());
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
  }

  private static KeyPair ecKeyPair() throws Exception {
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
