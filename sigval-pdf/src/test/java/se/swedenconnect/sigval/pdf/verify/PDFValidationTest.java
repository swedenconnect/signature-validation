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
package se.swedenconnect.sigval.pdf.verify;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSigner;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.swedenconnect.sigval.commons.timestamp.impl.BasicTimstampPolicyVerifier;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContextFactory;
import se.swedenconnect.sigval.pdf.svt.PDFSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.pdf.svt.PDFSVTValidator;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.DefaultPDFDocTimestampSignatureInterface;
import se.swedenconnect.sigval.pdf.timestamp.issue.impl.PDFDocTimstampProcessor;
import se.swedenconnect.sigval.pdf.verify.impl.PDFSingleSignatureValidatorImpl;
import se.swedenconnect.sigval.pdf.verify.impl.SVTenabledPDFDocumentSigVerifier;
import se.swedenconnect.sigval.pdf.verify.policy.impl.PkixPdfSignaturePolicyValidator;
import se.swedenconnect.sigval.svt.algorithms.SVTAlgoRegistry;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.testca.SigValTestExtension;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end PDF (PAdES) signature validation tests. A blank PDF is signed at test time with a certificate issued by
 * the embedded test CA (via {@link DefaultPDFSigner}), then validated through {@link SVTenabledPDFDocumentSigVerifier}.
 * Covers a trusted valid signature and an untrusted signer. (SVT for PDF is delivered as a document timestamp and is
 * added in a follow-up.)
 */
class PDFValidationTest {

  private static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair signerKeyPair;

  @BeforeAll
  static void init() throws Exception {
    signerKeyPair = ecKeyPair();
  }

  @Test
  void validSignature_isTrustedAndValid() throws Exception {
    final X509Certificate signerCert = issueEndEntity("PDF Signer", signerKeyPair.getPublic());
    final byte[] signed = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    final ExtendedPdfSigValResult result = validateFirst(signed);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
  }

  @Test
  void untrustedSigner_isRejected() throws Exception {
    final KeyPair kp = ecKeyPair();
    final X509Certificate selfSigned = selfSigned(kp, "CN=Untrusted PDF Signer");
    final byte[] signed = signPdf(credential(kp.getPrivate(), selfSigned));

    final ExtendedPdfSigValResult result = validateFirst(signed);

    assertEquals(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, result.getStatus());
  }

  @Test
  void svtRoundTrip_validatesViaSvt() throws Exception {
    // 1. A trusted, valid PDF signature.
    final X509Certificate signerCert = issueEndEntity("SVT PDF Signer", signerKeyPair.getPublic());
    final byte[] signedPdf = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    // 2. Issue the SVT (as a JWT), signed by a separate test-CA credential. certRef=false embeds the SVT signer
    // chain (x5c) so the PDF SVT validator - which has no supporting-cert parameter - can locate it.
    final KeyPair svtKeyPair = ecKeyPair();
    // The SVT is sealed as a document timestamp, so its signer must be a TSA-qualified certificate
    // (critical id-kp-timeStamping ExtendedKeyUsage), as required by RFC 3161 / BouncyCastle.
    final X509Certificate svtCert = issueTimestampCertificate("SVT Issuer", svtKeyPair.getPublic());
    final List<X509Certificate> svtChain = List.of(svtCert, CA.getTestCA().getIssuingCACertificate());
    final PDFSVTSigValClaimsIssuer claimsIssuer = new PDFSVTSigValClaimsIssuer(
        JWSAlgorithm.ES256, svtKeyPair.getPrivate(), svtChain, documentVerifier(null));
    final SVTModel svtModel = SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .certRef(false)
        .validityPeriod(Duration.ofDays(365).toMillis())
        .build();
    final SignedJWT svtJwt = claimsIssuer.getSignedSvtJWT(signedPdf, svtModel);
    assertNotNull(svtJwt, "an SVT should be issued for the valid, trusted signature");

    // 3. Seal the SVT into the PDF as a document timestamp signed by the SVT credential.
    final DefaultPDFDocTimestampSignatureInterface tsSigner = new DefaultPDFDocTimestampSignatureInterface(
        svtKeyPair.getPrivate(), svtChain, SVTAlgoRegistry.getAlgoParams(JWSAlgorithm.ES256).getSigAlgoId());
    final byte[] svtSealedPdf = PDFDocTimstampProcessor.createSVTSealedPDF(
        signedPdf, svtJwt.serialize(), tsSigner).getDocument();

    // 4. Validate the SVT-sealed PDF; the result must be produced via the SVT path.
    final PDFSVTValidator svtValidator = new PDFSVTValidator(certificateValidator(),
        new BasicTimstampPolicyVerifier(certificateValidator()));
    final List<SignatureValidationResult> results = documentVerifier(svtValidator).validate(svtSealedPdf);
    final ExtendedPdfSigValResult result = (ExtendedPdfSigValResult) results.get(0);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
    assertNotNull(result.getSvtJWT(), "result must be produced via the SVT validation path");
  }

  // ---- helpers ----

  private ExtendedPdfSigValResult validateFirst(final byte[] signedPdf) throws Exception {
    final List<SignatureValidationResult> results = documentVerifier(null).validate(signedPdf);
    return (ExtendedPdfSigValResult) results.get(0);
  }

  /** Builds a document verifier, optionally SVT-aware. */
  private SVTenabledPDFDocumentSigVerifier documentVerifier(final PDFSVTValidator svtValidator) throws Exception {
    final StatusCheckingCertificateValidatorImpl certValidator = certificateValidator();
    final TimeStampPolicyVerifier tsVerifier = new BasicTimstampPolicyVerifier(certValidator);
    final PDFSingleSignatureValidatorImpl singleValidator = new PDFSingleSignatureValidatorImpl(
        certValidator, new PkixPdfSignaturePolicyValidator(false), tsVerifier);
    return svtValidator == null
        ? new SVTenabledPDFDocumentSigVerifier(singleValidator, new DefaultPDFSignatureContextFactory())
        : new SVTenabledPDFDocumentSigVerifier(singleValidator, svtValidator, new DefaultPDFSignatureContextFactory());
  }

  private static byte[] signPdf(final PkiCredential credential) throws Exception {
    final DefaultPDFSigner signer = new DefaultPDFSigner(credential, ECDSA_SHA256);
    signer.setIncludeCertificateChain(true);
    final PDFSignerResult result = signer.sign(blankPdf());
    return result.getSignedDocument();
  }

  private static byte[] blankPdf() throws Exception {
    try (PDDocument doc = new PDDocument()) {
      doc.addPage(new PDPage());
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      doc.save(baos);
      return baos.toByteArray();
    }
  }

  private static PkiCredential credential(final PrivateKey key, final X509Certificate... chain) {
    return new BasicCredential(List.of(chain), key);
  }

  private CRLCache crlCache() throws Exception {
    return new InMemoryCRLCache(0, CA.getTestCA().createCRLDataLoader());
  }

  private StatusCheckingCertificateValidatorImpl certificateValidator() throws Exception {
    final StatusCheckingCertificateValidatorImpl validator = new StatusCheckingCertificateValidatorImpl(
        crlCache(), null, CA.getTestCA().getRootCACertificate());
    validator.setSingleThreaded(true);
    return validator;
  }

  private static X509Certificate issueEndEntity(final String commonName, final PublicKey publicKey) throws Exception {
    final DefaultCertificateModelBuilder builder = CA.getTestCA().getIssuingCA()
        .getCertificateModelBuilder(name(commonName), publicKey)
        .ocspServiceUrl(null);
    return CAUtils.getCert(CA.getTestCA().getIssuingCA().issueCertificate(builder.build()));
  }

  /** Issues a TSA-qualified certificate (critical id-kp-timeStamping EKU) for signing the SVT document timestamp. */
  private static X509Certificate issueTimestampCertificate(final String commonName, final PublicKey publicKey)
      throws Exception {
    final DefaultCertificateModelBuilder builder = CA.getTestCA().getIssuingCA()
        .getCertificateModelBuilder(name(commonName), publicKey)
        .ocspServiceUrl(null)
        .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_timeStamping));
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
