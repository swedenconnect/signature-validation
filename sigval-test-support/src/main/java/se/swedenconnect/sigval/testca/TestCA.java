/*
 * Copyright 2021-2025 Sweden Connect
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.utils.printcert.PrintCertificate;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.revocation.ocsp.impl.RepositoryBasedOCSPResponder;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import org.bouncycastle.asn1.x509.KeyUsage;
import java.security.cert.X509Certificate;

/**
 * Facade for a three-tier embedded test CA hierarchy:
 * <pre>
 *   Root CA  (self-signed, 10-year validity)
 *     └── Issuing CA  (issued by Root, 10-year validity)
 *              └── End-entity signing certificates (1-year validity)
 * </pre>
 *
 * <p>All revocation data (CRL, OCSP) is served in-memory. Pair this facade with
 * {@link TestCRLDataLoader} and {@link TestOCSPDataLoader} to wire up validators without
 * any HTTP network calls.
 *
 * <p>CRL and OCSP URLs embedded in issued certificates:
 * <ul>
 *   <li>{@value #ROOT_CRL_URL} — Root CA's CRL (embedded in Issuing CA cert)</li>
 *   <li>{@value #ISSUING_CRL_URL} — Issuing CA's CRL (embedded in end-entity certs)</li>
 *   <li>{@value #ISSUING_OCSP_URL} — Issuing CA's OCSP (embedded in end-entity certs)</li>
 * </ul>
 */
@Slf4j
public class TestCA {

  /** CRL URL embedded in the Issuing CA certificate (issued by Root CA). */
  public static final String ROOT_CRL_URL = "http://test-ca.local/root/crl";

  /** CRL URL embedded in end-entity certificates (issued by Issuing CA). */
  public static final String ISSUING_CRL_URL = "http://test-ca.local/issuing/crl";

  /** OCSP URL embedded in end-entity certificates. */
  public static final String ISSUING_OCSP_URL = "http://test-ca.local/issuing/ocsp";

  /** Default signing algorithm used for both CAs and issued certificates. */
  public static final String DEFAULT_ALGORITHM = CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA256;

  @Getter
  private final RootCAService rootCA;

  @Getter
  private final IssuerCAService issuingCA;

  private final InMemoryCARepository issuingRepository;

  private TestCA(final RootCAService rootCA,
      final IssuerCAService issuingCA,
      final InMemoryCARepository issuingRepository) {
    this.rootCA = rootCA;
    this.issuingCA = issuingCA;
    this.issuingRepository = issuingRepository;
  }

  /**
   * Creates a default {@code TestCA} using EC P-256 keys and {@value #DEFAULT_ALGORITHM}.
   *
   * @return fully initialised TestCA ready for use
   * @throws Exception on any crypto or CA setup failure
   */
  public static TestCA createDefault() throws Exception {
    return create(DEFAULT_ALGORITHM, "P-256");
  }

  /**
   * Creates a {@code TestCA} with the given signing algorithm and EC curve.
   *
   * @param algorithm XML algorithm URI, e.g. {@link CAAlgorithmRegistry#ALGO_ID_SIGNATURE_ECDSA_SHA256}
   * @param ecCurve   EC curve name for key generation, e.g. {@code "P-256"}
   * @return fully initialised TestCA
   * @throws Exception on any crypto or CA setup failure
   */
  public static TestCA create(final String algorithm, final String ecCurve) throws Exception {
    ensureBouncyCastle();

    final KeyPair rootKeyPair = generateEcKeyPair(ecCurve);
    final KeyPair issuingKeyPair = generateEcKeyPair(ecCurve);

    // --- Root CA (self-signed) ---
    final X509CertificateHolder rootCert = createSelfSignedRootCert(rootKeyPair, algorithm, "Test Root CA");
    final InMemoryCARepository rootRepository = new InMemoryCARepository();
    final PkiCredential rootCredential = new BasicCredential(
        List.of(CAUtils.getCert(rootCert)), rootKeyPair.getPrivate());
    final RootCAService rootCA = new RootCAService(rootCredential, rootRepository, algorithm, ROOT_CRL_URL);

    // --- Issuing CA (issued by Root CA) ---
    final DefaultCertificateModelBuilder issuingCertBuilder =
        rootCA.getCertificateModelBuilder(caName("Test Issuing CA"), issuingKeyPair.getPublic());
    final X509CertificateHolder issuingCert = rootCA.issueCertificate(issuingCertBuilder.build());
    final List<X509CertificateHolder> issuingChain = Arrays.asList(issuingCert, rootCert);
    final InMemoryCARepository issuingRepository = new InMemoryCARepository();
    final PkiCredential issuingCredential = new BasicCredential(
        CAUtils.getCertList(issuingChain), issuingKeyPair.getPrivate());
    final IssuerCAService issuingCA = new IssuerCAService(
        issuingCredential, issuingRepository, algorithm, ISSUING_CRL_URL, ISSUING_OCSP_URL);

    // --- OCSP responder on Issuing CA (uses CA key directly) ---
    final OCSPModel ocspModel = new OCSPModel(issuingCA.getCaCertificate(), algorithm);
    final OCSPResponder ocspResponder = new RepositoryBasedOCSPResponder(
        issuingCredential, ocspModel, issuingRepository);
    issuingCA.setOcspResponder(ocspResponder, issuingCA.getCaCertificate());

    log.info("Test CA hierarchy initialised: Root CA → Issuing CA [algorithm={}]", algorithm);

    return new TestCA(rootCA, issuingCA, issuingRepository);
  }

  /**
   * Issues an end-entity signing certificate for the given public key.
   *
   * @param publicKey subject public key
   * @param subjectCN common name for the certificate subject
   * @return the issued certificate as a JCA {@link X509Certificate}
   * @throws Exception on issuance failure
   */
  public X509Certificate issueSigningCertificate(final PublicKey publicKey, final String subjectCN)
      throws Exception {
    final DefaultCertificateModelBuilder builder =
        issuingCA.getCertificateModelBuilder(signerName(subjectCN), publicKey);
    final X509CertificateHolder holder = issuingCA.issueCertificate(builder.build());
    final X509Certificate cert = CAUtils.getCert(holder);
    logCertificate(cert, "Issued signing certificate");
    return cert;
  }

  /**
   * Logs a certificate using {@link PrintCertificate}. Safe to call even if logging is
   * disabled — the expensive {@code toString()} call is guarded by the debug check.
   *
   * @param cert  the certificate to log
   * @param label a short label shown before the certificate dump
   */
  public void logCertificate(final X509Certificate cert, final String label) {
    if (log.isDebugEnabled()) {
      try {
        log.debug("{}\n{}", label, new PrintCertificate(cert).toString());
      }
      catch (Exception e) {
        log.warn("Could not print certificate '{}': {}", label, e.getMessage());
      }
    }
  }

  /**
   * Revokes a previously issued end-entity certificate.
   *
   * @param serialNumber serial number of the certificate to revoke
   * @throws CertificateRevocationException if the certificate cannot be found or revoked
   * @throws IOException if the updated CRL cannot be published
   */
  public void revokeSigningCertificate(final BigInteger serialNumber)
      throws CertificateRevocationException, IOException {
    issuingCA.revokeCertificate(serialNumber, new java.util.Date());
    issuingCA.publishNewCrl();
  }

  /**
   * Returns the DER-encoded CRL for the given URL. The URL must match either
   * {@value #ROOT_CRL_URL} or {@value #ISSUING_CRL_URL}; the actual network address
   * is irrelevant — this method routes purely by URL string.
   *
   * @param url the CRL distribution point URL as embedded in a certificate
   * @return DER-encoded CRL bytes
   * @throws IOException if the URL is not recognised or the CRL cannot be encoded
   */
  public byte[] getCRL(final String url) throws IOException {
    if (ROOT_CRL_URL.equals(url)) {
      return rootCA.getCurrentCrl().getEncoded();
    }
    if (ISSUING_CRL_URL.equals(url)) {
      return issuingCA.getCurrentCrl().getEncoded();
    }
    throw new IOException("Unknown CRL URL (not managed by this TestCA): " + url);
  }

  /**
   * Returns an OCSP response for the given request. The URL must match
   * {@value #ISSUING_OCSP_URL}; the actual network address is irrelevant.
   *
   * @param url     the OCSP responder URL as embedded in a certificate
   * @param ocspReq the OCSP request produced by the validator
   * @return the signed OCSP response
   * @throws IOException                    if the URL is not recognised
   * @throws CertificateRevocationException if the OCSP responder cannot handle the request
   */
  public OCSPResp getOCSPResponse(final String url, final OCSPReq ocspReq)
      throws IOException, CertificateRevocationException {
    if (ISSUING_OCSP_URL.equals(url)) {
      // OCSPReq (high-level BC) → OCSPRequest (ASN.1, used by OCSPResponder interface)
      final OCSPRequest asn1Request = OCSPRequest.getInstance(ocspReq.getEncoded());
      return issuingCA.getOCSPResponder().handleRequest(asn1Request);
    }
    throw new IOException("Unknown OCSP URL (not managed by this TestCA): " + url);
  }

  /**
   * Returns the Root CA certificate as a JCA {@link X509Certificate}.
   */
  public X509Certificate getRootCACertificate() throws Exception {
    return CAUtils.getCert(rootCA.getCaCertificate());
  }

  /**
   * Returns the Issuing CA certificate as a JCA {@link X509Certificate}.
   */
  public X509Certificate getIssuingCACertificate() throws Exception {
    return CAUtils.getCert(issuingCA.getCaCertificate());
  }

  /**
   * Returns the trust anchors to use when configuring certificate path validators.
   * For this hierarchy, that is just the Root CA certificate.
   */
  public List<X509Certificate> getTrustAnchors() throws Exception {
    return List.of(getRootCACertificate());
  }

  /**
   * Creates a {@link TestCRLDataLoader} pre-wired to this {@code TestCA}.
   */
  public TestCRLDataLoader createCRLDataLoader() {
    return new TestCRLDataLoader(this);
  }

  /**
   * Creates a {@link TestOCSPDataLoader} pre-wired to this {@code TestCA}.
   */
  public TestOCSPDataLoader createOCSPDataLoader() {
    return new TestOCSPDataLoader(this);
  }

  // ---- private helpers ----

  private static void ensureBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static KeyPair generateEcKeyPair(final String curve) throws Exception {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec(curve));
    return kpg.generateKeyPair();
  }

  private static X509CertificateHolder createSelfSignedRootCert(
      final KeyPair keyPair, final String algorithm, final String cn) throws Exception {

    final CertificateIssuer selfIssuer = new SelfIssuedCertificateIssuer(
        new CertificateIssuerModel(algorithm, Duration.ofDays(2 * 3650 + 5)));

    return selfIssuer.issueCertificate(
        SelfIssuedCertificateModelBuilder.getInstance(keyPair, selfIssuer.getCertificateIssuerModel())
            .subject(caName(cn))
            .basicConstraints(new BasicConstraintsModel(true, true))
            .includeSki(true)
            .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
            .certificatePolicy(new CertificatePolicyModel(true))
            .build());
  }

  private static CertNameModel<?> caName(final String cn) {
    return new ExplicitCertNameModel(List.of(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.C).value("SE").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.O).value("Sweden Connect Test").build(),
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value(cn).build()));
  }

  private static CertNameModel<?> signerName(final String cn) {
    return new ExplicitCertNameModel(List.of(
        AttributeTypeAndValueModel.builder().attributeType(CertAttributes.CN).value(cn).build()));
  }
}
