/*
 * Copyright (c) 2020. IDsec Solutions AB
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
package se.idsec.sigval.pdf.timestamp.issue.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.pdf.timestamp.issue.PDFDocTimestampSignatureInterface;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Implementation of the PDF box signing interface used to add a document timestamp to a PDF document
 * which includes a SVT token.
 *
 * This implementation generates the timestamp as part of this service.
 * Another implementation of this interface could allow an external time stamp service to provide the timestamp.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPDFDocTimestampSignatureInterface implements PDFDocTimestampSignatureInterface {

  private static final String SVT_TOKEN_EXTENSION_OID = "1.2.752.201.5.2";
  private static final SecureRandom RNG = new SecureRandom();

  /** Private key used to perform the signature. */
  private final PrivateKey privateKey;

  /** The certificates of the signer. */
  private final List<X509Certificate> certificates;

  /** The signature algorithm to used, specified as a URI identifier. */
  private final String algorithm;

  /** The Signature Validation Token to be included in an extension to the timestamp */
  private String svt;

  /**
   * AN identifier of the time stamp policy
   * @param timeStampPolicyOid the OID declaring the time stamp policy
   */
  @Setter private ASN1ObjectIdentifier timeStampPolicyOid;

  /** CMS Signed data result. */
  private byte[] cmsSignedData;

  /** The CMS Signed attributes result. */
  private byte[] cmsSignedAttributes;

  /**
   * Constructor.
   *
   * @param privateKey   private signing key
   * @param certificates signing certificate chain
   * @param algorithm    signing algorithm
   */
  public DefaultPDFDocTimestampSignatureInterface(final PrivateKey privateKey, final List<X509Certificate> certificates,
    final String algorithm) {
    this.privateKey = privateKey;
    this.certificates = certificates;
    this.algorithm = algorithm;
    this.timeStampPolicyOid = SigValIdentifiers.ID_SVT_TS_POLICY;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getCmsSignedData() {
    return this.cmsSignedData;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getCmsSignedAttributes() {
    return this.cmsSignedAttributes;
  }

  /** {@inheritDoc} */
  @Override public List<X509Certificate> getCertificateChain() {
    return certificates;
  }

  /** {@inheritDoc} */
  @Override public void setSvt(String svt) {
    this.svt = svt;
  }

  /** {@inheritDoc} */
  @Override public String getSvt() {
    return svt;
  }

  /**
   * SignatureInterface implementation.
   * <p>
   * This method will be called from inside of the pdfbox and creates the PKCS #7 signature (CMS ContentInfo). The given
   * InputStream contains the bytes that are given by the byte range.
   * </p>
   *
   * @param content the message bytes being signed (specified by ByteRange in the signature dictionary)
   * @return CMS ContentInfo bytes holding the complete PKCS#7 signature structure
   * @throws IOException error during signature creation
   */
  @Override
  public byte[] sign(final InputStream content) throws IOException {

    if (svt == null || svt.length() ==0) throw new IOException("The SVT must not be null or empty");

    try {
      // Get the digest algorithm OID
      ASN1ObjectIdentifier digestAlgoOID = PDFAlgorithmRegistry.getAlgorithmProperties(algorithm).getDigestAlgoOID();

      //List<Certificate> certList = Arrays.asList(certificates);
      Store certs = new JcaCertStore(certificates);
      org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
        ASN1Primitive.fromByteArray(certificates.get(0).getEncoded()));
      byte[] document = IOUtils.toByteArray(content);
      byte[] digest = PDFAlgorithmRegistry.getMessageDigestInstance(algorithm).digest(document);

      //Generate tsRequest
      TimeStampRequestGenerator tsReqGen = new TimeStampRequestGenerator();
      tsReqGen.setCertReq(true);
      //Add SVA extension
      tsReqGen.addExtension(new ASN1ObjectIdentifier(SVT_TOKEN_EXTENSION_OID),
        false,
        svt.getBytes(StandardCharsets.UTF_8)
      );
      tsReqGen.setReqPolicy(timeStampPolicyOid);
      TimeStampRequest tsReq = tsReqGen.generate(digestAlgoOID, digest);

      //Time Stamp token generation
      DigestCalculator dgCalc = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(digestAlgoOID));
      ContentSigner signer = new JcaContentSignerBuilder(PDFAlgorithmRegistry.getSigAlgoName(algorithm)).build(privateKey);
      JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
        new JcaDigestCalculatorProviderBuilder().build());
      SignerInfoGenerator siGen = builder.build(signer, new X509CertificateHolder(cert));
      // We set the policy in the request so we pass null here
      TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(siGen, dgCalc, null);
      tstGen.addCertificates(certs);
      // Optionally we include the cert subject name as the TSA general name as tag [4] = Name (Which is equal to RDNSequence held in the cert subject field)
      tstGen.setTSA(new GeneralName(4, cert.getSubject().toASN1Primitive()));
      /* Set the parameters e.g. set the accuracy or include the signing certificate */
      TimeStampToken tst = tstGen.generate(tsReq, new BigInteger(60, RNG), new Date());
          /*
            NOTE: We choose to encode the time stamp token (Which is actually the full CMS ContentInfo) with DL = Definite Length encoding.
            The reason for this is that Bouncycastle by default choose BER encoding which by default choose constructed indefinite length encoding.
            This is legal CMS syntax, but inefficient and confusing. Choosing DL means that we avoid the double wrapping of OCTET STRING when
            including the RFC 3161 TSTInfo as DER encoded bytes inside EncapsulatedContentInfo.

            Changing encoding to DL does NOT affect the signature as the signature covers the data inside OCTET STRING, but not the OCTET STRING tag
            itself.
          */
      byte[] tstBytes = tst.toCMSSignedData().toASN1Structure().getEncoded(ASN1Encoding.DL);

      // Clear the SVT in case this interface implementation is re-used. Forcing the svt to be set each time
      svt = null;

      return tstBytes;
    }
    catch (Exception e) {
      throw new IOException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isPades() {
    return false;
  }

}
