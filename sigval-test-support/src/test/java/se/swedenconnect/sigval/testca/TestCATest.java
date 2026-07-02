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

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke tests for the embedded test CA infrastructure.
 * Verifies that the three-tier hierarchy initialises correctly, issues valid certificates,
 * and that CRL and OCSP revocation data are served correctly through the data loaders.
 */
class TestCATest {

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
  void testCAHierarchyInitialises() throws Exception {
    final TestCA testCA = CA.getTestCA();
    assertNotNull(testCA.getRootCA(), "Root CA should be initialised");
    assertNotNull(testCA.getIssuingCA(), "Issuing CA should be initialised");
    assertNotNull(testCA.getRootCACertificate(), "Root CA certificate should be present");
    assertNotNull(testCA.getIssuingCACertificate(), "Issuing CA certificate should be present");
    assertNotNull(testCA.getIssuingCA().getOCSPResponder(), "OCSP responder should be configured");
  }

  @Test
  void testIssuedCertificateIsValid() throws Exception {
    final X509Certificate cert = CA.getTestCA().issueSigningCertificate(
        subjectKeyPair.getPublic(), "Test Signer");

    assertNotNull(cert);
    assertEquals("CN=Test Signer", cert.getSubjectX500Principal().getName());
    // Certificate should currently be valid
    assertDoesNotThrow(() -> cert.checkValidity());
    // Signed by the Issuing CA
    final X509Certificate issuingCACert = CA.getTestCA().getIssuingCACertificate();
    assertDoesNotThrow(() -> cert.verify(issuingCACert.getPublicKey()));
  }

  @Test
  void testCRLIssuingCAIsServedCorrectly() throws Exception {
    final byte[] crlBytes = CA.getTestCA().getCRL(TestCA.ISSUING_CRL_URL);
    assertNotNull(crlBytes);
    assertTrue(crlBytes.length > 0, "CRL should not be empty");
  }

  @Test
  void testCRLRootIsServedCorrectly() throws Exception {
    final byte[] crlBytes = CA.getTestCA().getCRL(TestCA.ROOT_CRL_URL);
    assertNotNull(crlBytes);
    assertTrue(crlBytes.length > 0, "Root CRL should not be empty");
  }

  @Test
  void testCRLUnknownUrlThrows() {
    assertThrows(Exception.class,
        () -> CA.getTestCA().getCRL("http://unknown.example.com/crl"));
  }

  @Test
  void testOCSPGoodStatus() throws Exception {
    final TestCA testCA = CA.getTestCA();
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("P-256"));
    final X509Certificate cert = testCA.issueSigningCertificate(
        kpg.generateKeyPair().getPublic(), "OCSP Test Subject");

    final OCSPResp response = fetchOCSP(testCA, cert);

    assertEquals(OCSPResp.SUCCESSFUL, response.getStatus());
    final BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
    final SingleResp singleResp = basicResp.getResponses()[0];
    assertEquals(CertificateStatus.GOOD, singleResp.getCertStatus(),
        "Certificate should have GOOD status");
  }

  @Test
  void testOCSPRevokedStatus() throws Exception {
    final TestCA testCA = CA.getTestCA();
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
    kpg.initialize(new ECGenParameterSpec("P-256"));
    final X509Certificate cert = testCA.issueSigningCertificate(
        kpg.generateKeyPair().getPublic(), "Revoked Subject");

    testCA.revokeSigningCertificate(cert.getSerialNumber());

    final OCSPResp response = fetchOCSP(testCA, cert);

    assertEquals(OCSPResp.SUCCESSFUL, response.getStatus());
    final BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
    final SingleResp singleResp = basicResp.getResponses()[0];
    assertInstanceOf(RevokedStatus.class, singleResp.getCertStatus(),
        "Certificate should have REVOKED status");
  }

  @Test
  void testDataLoadersAreCreated() {
    final TestCA testCA = CA.getTestCA();
    assertNotNull(testCA.createCRLDataLoader());
    assertNotNull(testCA.createOCSPDataLoader());
  }

  // ---- helpers ----

  private static OCSPResp fetchOCSP(final TestCA testCA, final X509Certificate cert) throws Exception {
    // Build a minimal OCSP request using BouncyCastle
    final org.bouncycastle.cert.jcajce.JcaX509CertificateHolder certHolder =
        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert);
    final org.bouncycastle.cert.jcajce.JcaX509CertificateHolder issuerHolder =
        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(testCA.getIssuingCACertificate());
    final org.bouncycastle.cert.ocsp.CertificateID certId =
        new org.bouncycastle.cert.ocsp.CertificateID(
            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build()
                .get(org.bouncycastle.cert.ocsp.CertificateID.HASH_SHA1),
            issuerHolder,
            cert.getSerialNumber());
    final org.bouncycastle.cert.ocsp.OCSPReqBuilder reqBuilder =
        new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
    reqBuilder.addRequest(certId);
    final org.bouncycastle.cert.ocsp.OCSPReq ocspReq = reqBuilder.build();

    return testCA.getOCSPResponse(TestCA.ISSUING_OCSP_URL, ocspReq);
  }
}
