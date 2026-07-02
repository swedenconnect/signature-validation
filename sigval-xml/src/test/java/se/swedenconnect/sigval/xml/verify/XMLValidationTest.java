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
package se.swedenconnect.sigval.xml.verify;

import org.apache.xml.security.Init;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.nimbusds.jose.JWSAlgorithm;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.sigval.cert.chain.impl.StatusCheckingCertificateValidatorImpl;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.impl.InMemoryCRLCache;
import se.swedenconnect.sigval.commons.svt.SVTExtendpolicy;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.xml.data.ExtendedXmlSigvalResult;
import se.swedenconnect.sigval.xml.policy.impl.PkixXmlSignaturePolicyValidator;
import se.swedenconnect.sigval.xml.svt.XMLDocumentSVTIssuer;
import se.swedenconnect.sigval.xml.svt.XMLSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.xml.svt.XMLSVTValidator;
import se.swedenconnect.sigval.xml.verify.impl.XMLSignatureElementValidatorImpl;
import se.swedenconnect.sigval.xml.verify.impl.XMLSignedDocumentValidator;
import se.swedenconnect.sigval.testca.SigValTestExtension;

import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
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
 * End-to-end XML (XML-DSig) signature validation tests. An enveloped signature is created at test time with a
 * certificate issued by the embedded test CA (via {@link DefaultXMLSigner}), then validated through
 * {@link XMLSignedDocumentValidator}. Covers a trusted valid signature, an untrusted signer, and an SVT round-trip.
 */
class XMLValidationTest {

  @RegisterExtension
  static final SigValTestExtension CA = new SigValTestExtension();

  private static KeyPair signerKeyPair;

  @BeforeAll
  static void init() throws Exception {
    if (!Init.isInitialized()) {
      Init.init();
    }
    signerKeyPair = ecKeyPair();
  }

  @Test
  void validSignature_isTrustedAndValid() throws Exception {
    final X509Certificate signerCert = issueEndEntity("XML Signer", signerKeyPair.getPublic());
    final Document signed = signXml("Signed XML payload",
        credential(signerKeyPair.getPrivate(), signerCert, CA.getTestCA().getIssuingCACertificate()));

    final ExtendedXmlSigvalResult result = validateFirst(signed, null);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
  }

  @Test
  void untrustedSigner_isRejected() throws Exception {
    final KeyPair kp = ecKeyPair();
    final X509Certificate selfSigned = selfSigned(kp, "CN=Untrusted XML Signer");
    final Document signed = signXml("Signed XML payload", credential(kp.getPrivate(), selfSigned));

    final ExtendedXmlSigvalResult result = validateFirst(signed, null);

    assertEquals(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, result.getStatus());
  }

  @Test
  void svtRoundTrip_validatesViaSvt() throws Exception {
    // 1. A trusted, valid XML signature.
    final X509Certificate signerCert = issueEndEntity("SVT XML Signer", signerKeyPair.getPublic());
    final Document signed = signXml("Signed XML payload",
        credential(signerKeyPair.getPrivate(), signerCert, CA.getTestCA().getIssuingCACertificate()));

    // 2. Issue an SVT over it, signed by a separate test-CA credential.
    final KeyPair svtKeyPair = ecKeyPair();
    final X509Certificate svtCert = issueEndEntity("SVT Issuer", svtKeyPair.getPublic());
    final XMLSignatureElementValidatorImpl plainValidator = new XMLSignatureElementValidatorImpl(
        certificateValidator(), new PkixXmlSignaturePolicyValidator(false), null);
    final XMLSVTSigValClaimsIssuer claimsIssuer = new XMLSVTSigValClaimsIssuer(
        JWSAlgorithm.ES256, svtKeyPair.getPrivate(),
        List.of(svtCert, CA.getTestCA().getIssuingCACertificate()), plainValidator);
    final XMLDocumentSVTIssuer svtIssuer = new XMLDocumentSVTIssuer(claimsIssuer);
    final SVTModel svtModel = SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .certRef(true)
        .validityPeriod(Duration.ofDays(365).toMillis())
        .build();
    final byte[] svtDocumentBytes = svtIssuer.issueSvt(signed, svtModel, SVTExtendpolicy.REPLACE, false);

    // 3. Validate the SVT-extended document; the result must be produced via the SVT path.
    final XMLSVTValidator svtValidator = new XMLSVTValidator(certificateValidator(),
        List.of(svtCert, CA.getTestCA().getIssuingCACertificate()));
    final ExtendedXmlSigvalResult result = validateFirst(parse(svtDocumentBytes), svtValidator);

    assertEquals(SignatureValidationResult.Status.SUCCESS, result.getStatus());
    assertNotNull(result.getSvtJWT(), "result must be produced via the SVT validation path");
  }

  // ---- helpers ----

  private ExtendedXmlSigvalResult validateFirst(final Document document, final XMLSVTValidator svtValidator)
      throws Exception {
    final XMLSignatureElementValidatorImpl elementValidator = svtValidator == null
        ? new XMLSignatureElementValidatorImpl(certificateValidator(), new PkixXmlSignaturePolicyValidator(false), null)
        : new XMLSignatureElementValidatorImpl(certificateValidator(), new PkixXmlSignaturePolicyValidator(false), null,
            svtValidator);
    final XMLSignedDocumentValidator validator = new XMLSignedDocumentValidator(elementValidator);
    final List<SignatureValidationResult> results = validator.validate(document);
    return (ExtendedXmlSigvalResult) results.get(0);
  }

  private static Document signXml(final String text, final PkiCredential credential) throws Exception {
    final DefaultXMLSigner signer = new DefaultXMLSigner(credential);
    signer.setIncludeCertificateChain(true);
    final XMLSignerResult result = signer.sign(newDocument(text));
    return result.getSignedDocument();
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

  private static Document newDocument(final String text) throws Exception {
    final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    final Document doc = dbf.newDocumentBuilder().newDocument();
    final Element root = doc.createElement("root");
    root.setTextContent(text);
    doc.appendChild(root);
    return doc;
  }

  private static Document parse(final byte[] xml) throws Exception {
    final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
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
