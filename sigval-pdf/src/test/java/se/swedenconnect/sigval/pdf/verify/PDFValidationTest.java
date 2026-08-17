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
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
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
import se.swedenconnect.sigval.pdf.pdfstruct.PDFDocRevision;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultGeneralSafeObjects;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContext;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
  void tamperedSignature_isRejected() throws Exception {
    final X509Certificate signerCert = issueEndEntity("PDF Signer", signerKeyPair.getPublic());
    final byte[] signed = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    // Alter a byte inside the signed byte-range (the PDF header version), leaving the signature dictionary,
    // /Contents (the CMS) and the certificate chain untouched. The signed digest no longer matches, so the
    // CMS signature verification must fail. This pins that the verify() result is actually enforced.
    final byte[] tampered = tamperSignedContent(signed);

    final ExtendedPdfSigValResult result = validateFirst(tampered);

    assertEquals(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, result.getStatus(),
        "a PDF whose signed content was altered must be reported as invalid");
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

  @Test
  void svtWithForgedSignature_isRejected() throws Exception {
    final X509Certificate signerCert = issueEndEntity("SVT PDF Signer", signerKeyPair.getPublic());
    final byte[] signedPdf = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    // The document timestamp is signed correctly (matches svtCert), but the SVT JWT it carries is signed
    // with a DIFFERENT key while still presenting the trusted svtCert - a forged SVT.
    final KeyPair svtKeyPair = ecKeyPair();
    final X509Certificate svtCert = issueTimestampCertificate("SVT Issuer", svtKeyPair.getPublic());
    final List<X509Certificate> svtChain = List.of(svtCert, CA.getTestCA().getIssuingCACertificate());
    final KeyPair attackerKeyPair = ecKeyPair();

    final PDFSVTSigValClaimsIssuer forgingIssuer = new PDFSVTSigValClaimsIssuer(
        JWSAlgorithm.ES256, attackerKeyPair.getPrivate(), svtChain, documentVerifier(null));
    final SVTModel svtModel = SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .certRef(false)
        .validityPeriod(Duration.ofDays(365).toMillis())
        .build();
    final SignedJWT forgedSvtJwt = forgingIssuer.getSignedSvtJWT(signedPdf, svtModel);

    final DefaultPDFDocTimestampSignatureInterface tsSigner = new DefaultPDFDocTimestampSignatureInterface(
        svtKeyPair.getPrivate(), svtChain, SVTAlgoRegistry.getAlgoParams(JWSAlgorithm.ES256).getSigAlgoId());
    final byte[] svtSealedPdf = PDFDocTimstampProcessor.createSVTSealedPDF(
        signedPdf, forgedSvtJwt.serialize(), tsSigner).getDocument();

    final PDFSVTValidator svtValidator = new PDFSVTValidator(certificateValidator(),
        new BasicTimstampPolicyVerifier(certificateValidator()));
    final List<SignatureValidationResult> results = documentVerifier(svtValidator).validate(svtSealedPdf);
    final ExtendedPdfSigValResult result = (ExtendedPdfSigValResult) results.get(0);

    // The forged SVT must be rejected - validation must NOT be produced via the SVT path.
    assertNull(result.getSvtJWT(), "an SVT with an invalid signature must not be accepted");
  }

  /**
   * Build-time canary for PDFBox regressions. This library only ever grants "lenient" treatment to SVTs it produces
   * itself, and it relies on the fact that our SVT document-timestamp field is invisible (zero-area), so that it
   * passes the STRICT safe-update rules on its own - without depending on the validated-signature (trust) upgrade.
   * That property is what lets SVT re-issuance keep full document coverage even when an older SVT's key/algorithm no
   * longer validates at present time.
   *
   * <p>This test seals an SVT into a PDF exactly the way the library does (a PDFBox document timestamp), builds the
   * signature context the way production does (but WITHOUT running the validator, so no trust upgrade is applied), and
   * asserts that the SVT revision is a safe update under the strict rules. If a future PDFBox release changes how the
   * timestamp field is created (e.g. a non-zero {@code /Rect}), this fails loudly at build time - before it can
   * silently break coverage in production.</p>
   */
  @Test
  void svtTimestampField_isInvisibleUnderStrictRules() throws Exception {
    final X509Certificate signerCert = issueEndEntity("SVT PDF Signer", signerKeyPair.getPublic());
    final byte[] signedPdf = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    final KeyPair svtKeyPair = ecKeyPair();
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

    final DefaultPDFDocTimestampSignatureInterface tsSigner = new DefaultPDFDocTimestampSignatureInterface(
        svtKeyPair.getPrivate(), svtChain, SVTAlgoRegistry.getAlgoParams(JWSAlgorithm.ES256).getSigAlgoId());
    final byte[] svtSealedPdf = PDFDocTimstampProcessor.createSVTSealedPDF(
        signedPdf, svtJwt.serialize(), tsSigner).getDocument();

    // Build the context exactly as production does (DefaultGeneralSafeObjects) but WITHOUT running the validator, so
    // no trust upgrade is applied - every revision's isSafeUpdate() reflects the STRICT rules.
    final DefaultPDFSignatureContext context =
        new DefaultPDFSignatureContext(svtSealedPdf, new DefaultGeneralSafeObjects());
    final List<PDFDocRevision> revisions = context.getPdfDocRevisions();
    assertTrue(revisions.size() >= 3,
        "expected base + signature + SVT-timestamp revisions, got " + revisions.size());

    // The SVT document timestamp is the last incremental update.
    final PDFDocRevision svtRevision = revisions.get(revisions.size() - 1);
    assertTrue(svtRevision.isSafeUpdate(),
        "The SVT document-timestamp field must be recognised as invisible (zero-area) under the STRICT safe-update "
            + "rules, i.e. WITHOUT relying on the validated-signature upgrade. This just failed, which almost "
            + "certainly means a PDFBox change altered how the timestamp field is created (e.g. a non-zero /Rect). "
            + "Fix the field creation or the isInvisibleAnnotation rules before this reaches production - otherwise "
            + "SVT re-issuance will silently lose full document coverage once the older SVT is no longer trusted.");
  }

  /**
   * Regression for the "incomplete incremental update" bypass. Content appended after the last {@code %%EOF} - an
   * incremental update whose terminating {@code %%EOF} was removed - forms no recognized revision (the analysis slices
   * on {@code %%EOF}) so it is invisible to the coverage logic, yet recovering PDF viewers render it. Such trailing
   * non-whitespace content must force {@code isCoversWholeDocument} to false.
   */
  @Test
  void contentAfterLastEof_breaksCoverage() throws Exception {
    final X509Certificate signerCert = issueEndEntity("PDF Signer", signerKeyPair.getPublic());
    final byte[] signedPdf = signPdf(credential(signerKeyPair.getPrivate(), signerCert,
        CA.getTestCA().getIssuingCACertificate()));

    // Control: a plain signed document - the signature is the last revision and covers the whole document.
    final DefaultPDFSignatureContext cleanContext =
        new DefaultPDFSignatureContext(signedPdf, new DefaultGeneralSafeObjects());
    final PDSignature signature = cleanContext.getSignatures().get(0);
    assertTrue(cleanContext.isCoversWholeDocument(signature),
        "a plain signed document must cover the whole document");

    // Append forged content after the last %%EOF, with no terminating %%EOF of its own.
    final byte[] forgedTail =
        "\n<forged incremental update with no terminating EOF>\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    final byte[] tamperedPdf = new byte[signedPdf.length + forgedTail.length];
    System.arraycopy(signedPdf, 0, tamperedPdf, 0, signedPdf.length);
    System.arraycopy(forgedTail, 0, tamperedPdf, signedPdf.length, forgedTail.length);

    final DefaultPDFSignatureContext tamperedContext =
        new DefaultPDFSignatureContext(tamperedPdf, new DefaultGeneralSafeObjects());
    final PDSignature tamperedSignature = tamperedContext.getSignatures().get(0);
    assertFalse(tamperedContext.isCoversWholeDocument(tamperedSignature),
        "non-whitespace content after the last %%EOF must break whole-document coverage");
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

  /** Flips the PDF header version digit, which lies inside the signed byte-range but outside the signature
   * dictionary and its {@code /Contents}. PDFBox still parses the document (and the intact signature), but the
   * signed content digest no longer matches, so CMS verification fails. */
  private static byte[] tamperSignedContent(final byte[] signedPdf) {
    final byte[] copy = signedPdf.clone();
    final byte[] marker = "%PDF-1.".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    int idx = -1;
    outer:
    for (int i = 0; i + marker.length < copy.length; i++) {
      for (int j = 0; j < marker.length; j++) {
        if (copy[i + j] != marker[j]) {
          continue outer;
        }
      }
      idx = i + marker.length;
      break;
    }
    if (idx < 0) {
      throw new IllegalStateException("PDF header not found");
    }
    copy[idx] = (byte) (copy[idx] == '4' ? '5' : '4');
    return copy;
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
