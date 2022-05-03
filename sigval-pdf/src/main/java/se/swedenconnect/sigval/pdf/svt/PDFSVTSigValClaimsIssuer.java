/*
 * Copyright (c) 2020-2022. Sweden Connect
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
package se.swedenconnect.sigval.pdf.svt;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;

import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.svt.AbstractSVTSigValClaimsIssuer;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.swedenconnect.sigval.svt.algorithms.SVTAlgoRegistry;
import se.swedenconnect.sigval.svt.claims.SVTProfile;
import se.swedenconnect.sigval.svt.claims.SigReferenceClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;
import se.swedenconnect.sigval.svt.claims.SignedDataClaims;

/**
 * Representation of a SVT claims issuer.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFSVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<byte[]> {

  private final ExtendedPDFSignatureValidator signatureVerifier;

  /**
   * Constructor for the PDF SVT claims issuer. This class is not thread safe and an instance of this issuer must be
   * created for each instance of SVT creation.
   *
   * @param algorithm
   *          the algorithm used to sign the SVT
   * @param privateKey
   *          the private key used to sign the SVT
   * @param certificates
   *          certificates for validating the signature on the SVT
   * @param signatureVerifier
   *          signature verifier used to validate the signature on the PDF document
   * @throws JOSEException
   *           on JWT errors
   * @throws NoSuchAlgorithmException
   *           if the algorithm is not supported
   */
  public PDFSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey, List<X509Certificate> certificates,
      ExtendedPDFSignatureValidator signatureVerifier)
      throws JOSEException, NoSuchAlgorithmException {
    super(algorithm, privateKey, certificates);
    this.signatureVerifier = signatureVerifier;
  }

  /**
   * This method is called from within the SVT Issuer to perform signature validation and to collect the signature
   * validation claims as a result of this validation process
   *
   * @param signedDocument
   *          the signed document to validate
   * @throws IOException
   *           on error
   */
  @Override
  protected List<SignatureClaims> verify(byte[] signedDocument, String hashAlgoUri) throws IOException, SignatureException {
    SignedDocumentValidationResult<ExtendedPdfSigValResult> pdfSigVerifyResultDocument = signatureVerifier.extendedResultValidation(
      signedDocument);

    if (pdfSigVerifyResultDocument.getSignatureCount() < 1) {
      return new ArrayList<>();
    }
    // Loop through the signature validation results
    List<ExtendedPdfSigValResult> resultList = pdfSigVerifyResultDocument.getSignatureValidationResults();
    List<SignatureClaims> claimsResultsList = new ArrayList<>();

    for (ExtendedPdfSigValResult sigResult : resultList) {
      try {
        SignatureClaims claimsData = SignatureClaims.builder()
          .sig_ref(getSigRefData(sigResult.getSignedData(), hashAlgoUri))
          .sig_val(getSignaturePolicyValidations(sigResult))
          .sig_data_ref(getDocRefHashes(sigResult, signedDocument, hashAlgoUri))
          .time_val(
            sigResult.getTimeValidationResults()
              .stream()
              .map(timeValidationResult -> extractTimeValClaims(timeValidationResult, hashAlgoUri))
              .filter(timeValidationClaims -> isVerifiedTime(timeValidationClaims))
              .collect(Collectors.toList()))
          .signer_cert_ref(getCertRef(sigResult, hashAlgoUri))
          .build();
        claimsResultsList.add(claimsData);
      }
      catch (Exception e) {
        e.printStackTrace();
      }
    }
    return claimsResultsList;
  }

  /** {@inheritDoc} */
  @Override
  protected SVTProfile getSvtProfile() {
    return SVTProfile.PDF;
  }

  /**
   * Extract signed attributes and signature data and provide hash of both in a signature reference for an SVA claims
   * set.
   *
   * @param contentInfoBytes
   *          CMS Content info from PDF signature (The bytes provided as signature data in a PDF signature dictionary)
   * @return SignatureReference
   * @throws IOException
   *           if the content is not legal data
   */
  private SigReferenceClaims getSigRefData(byte[] contentInfoBytes, String hashAlgoUri) throws IOException, NoSuchAlgorithmException {
    ASN1InputStream asn1Stream = null;
    try {
      asn1Stream = new ASN1InputStream(contentInfoBytes);
      ContentInfo contentInfo = ContentInfo.getInstance(asn1Stream.readObject());
      if (!contentInfo.getContentType().equals(PKCSObjectIdentifiers.signedData)) {
        throw new IOException("Illegal content for PDF signature. Must contain SignedData");
      }
      SignedData signedData = SignedData.getInstance(contentInfo.getContent());
      SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
      byte[] sigAttrsEncBytes = signerInfo.getAuthenticatedAttributes().getEncoded("DER");
      byte[] signatureBytes = signerInfo.getEncryptedDigest().getOctets();

      return SigReferenceClaims.builder()
        .sig_hash(getB64Hash(signatureBytes, hashAlgoUri))
        .sb_hash(getB64Hash(sigAttrsEncBytes, hashAlgoUri))
        .build();
    }
    finally {
      if (asn1Stream != null) {
        try {
          asn1Stream.close();
        }
        catch (IOException e) {
        }
      }
    }
  }

  private List<SignedDataClaims> getDocRefHashes(ExtendedPdfSigValResult sigVerifyResult, byte[] signedDocument, String hashAlgoUri)
      throws IOException, NoSuchAlgorithmException {
    return Arrays.asList(calculateDocRefHash(sigVerifyResult.getPdfSignature(), signedDocument, hashAlgoUri));
  }

  /**
   * Performs the basic calculation of the hash of signed data in a PDF document, signed by a particular signature
   *
   * @param sig
   *          Signature
   * @param signedDocument
   *          signed document
   * @param hashAlgoUri
   *          hash algorithm URI identifier
   * @return Signed document data hashes
   * @throws IOException
   *           parsing errors
   * @throws NoSuchAlgorithmException
   *           unsupported algorithm
   */
  protected SignedDataClaims calculateDocRefHash(PDSignature sig, byte[] signedDocument, String hashAlgoUri) throws IOException,
      NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    byte[] digest = md.digest(sig.getSignedContent(signedDocument));
    int[] byteRange = sig.getByteRange();
    String ref = byteRange[0] + " " + byteRange[1] + " " + byteRange[2] + " " + byteRange[3];

    return SignedDataClaims.builder()
      .ref(ref)
      .hash(Base64.encodeBase64String(digest))
      .build();
  }

}
