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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.impl.SynchronizedCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Issuing CA service for the embedded test CA hierarchy. End-entity signing certificates
 * issued by this CA have a 1-year validity and embed {@code crlUrl} and {@code ocspUrl}
 * so that validators can retrieve revocation data via {@link TestCRLDataLoader} and
 * {@link TestOCSPDataLoader} without any HTTP network calls.
 */
public class IssuerCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final CertificateIssuer certificateIssuer;
  private final CRLIssuer crlIssuer;
  private final List<String> crlDistributionPoints;
  private final String ocspUrl;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;

  public IssuerCAService(final PkiCredential issuerCredential,
      final InMemoryCARepository caRepository,
      final String algorithm,
      final String crlUrl,
      final String ocspUrl)
      throws CertificateEncodingException, NoSuchAlgorithmException, IOException {

    super(issuerCredential, caRepository);
    this.ocspUrl = ocspUrl;

    this.certificateIssuer = new BasicCertificateIssuer(
        new CertificateIssuerModel(algorithm, Duration.ofDays(365)), issuerCredential);

    final CRLIssuerModel crlIssuerModel = buildCrlIssuerModel(algorithm, crlUrl);
    this.crlIssuer = new SynchronizedCRLIssuer(
        crlIssuerModel, caRepository.getCRLRevocationDataProvider(), issuerCredential);
    this.crlDistributionPoints = List.of(crlUrl);

    publishNewCrl();
  }

  private CRLIssuerModel buildCrlIssuerModel(final String algorithm, final String crlUrl)
      throws CertificateRevocationException {
    try {
      return new CRLIssuerModel(getCaCertificate(), algorithm, Duration.ofHours(2), crlUrl);
    }
    catch (Exception e) {
      throw new CertificateRevocationException(e);
    }
  }

  /**
   * Configures the OCSP responder for this CA. Called by {@link TestCA} after construction.
   */
  public void setOcspResponder(final OCSPResponder ocspResponder,
      final X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  @Override
  public CertificateIssuer getCertificateIssuer() {
    return certificateIssuer;
  }

  @Override
  protected CRLIssuer getCrlIssuer() {
    return crlIssuer;
  }

  @Override
  public OCSPResponder getOCSPResponder() {
    return ocspResponder;
  }

  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return ocspResponderCertificate;
  }

  @Override
  public String getCaAlgorithm() {
    return certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  @Override
  public List<String> getCrlDpURLs() {
    return crlDistributionPoints;
  }

  @Override
  public String getOCSPResponderURL() {
    return ocspResponder != null ? ocspUrl : null;
  }

  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(
      final CertNameModel<?> subject,
      final PublicKey publicKey,
      final X509CertificateHolder issuerCertificate,
      final CertificateIssuerModel certificateIssuerModel)
      throws CertificateIssuanceException {

    return DefaultCertificateModelBuilder.getInstance(publicKey, getCaCertificate(), certificateIssuerModel)
        .subject(subject)
        .includeAki(true)
        .includeSki(true)
        .basicConstraints(new BasicConstraintsModel(false, true))
        .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature + KeyUsage.nonRepudiation))
        .crlDistributionPoints(crlDistributionPoints)
        .ocspServiceUrl(ocspResponder != null ? ocspUrl : null);
  }
}
