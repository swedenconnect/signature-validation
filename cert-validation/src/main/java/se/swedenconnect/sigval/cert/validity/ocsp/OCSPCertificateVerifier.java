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

package se.swedenconnect.sigval.cert.validity.ocsp;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.sigval.cert.utils.CertUtils;
import se.swedenconnect.sigval.cert.validity.AbstractValidityChecker;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.ValidationStatus.CertificateValidity;
import se.swedenconnect.sigval.cert.validity.ValidationStatus.ValidatorSourceType;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * Certificate verifier based on OCSP
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class OCSPCertificateVerifier extends AbstractValidityChecker implements OCSPDataLoader {

  /** Event identifier used to identify this process */
  public static final String EVENT_ID = "ocsp-validity";
  /** Response status code names */
  public static final String[] RESPONSE_STATUS = new String[]{
    "SUCCESSFUL",
    "MALFORMED_REQUEST",
    "INTERNAL_ERROR",
    "TRY_LATER",
    "NO_USED",
    "SIG_REQUIRED",
    "UNAUTHORIZED"
  };

  /** The data loader used to get OCSP responses */
  @Setter OCSPDataLoader ocspDataLoader;
  /** timeout in milliseconds for making connections to an OCSP responder */
  @Setter protected int connectTimeout = 1000;
  /** timeout in milliseconds for obtaining an OCSP response */
  @Setter protected int readTimeout = 3000;
  /** boolean deciding if a nonce is included in the OCSP request */
  @Setter boolean includeNonce = true;
  /** Random source for nonce generation */
  public static final Random RNG = new SecureRandom();

  /** {@inheritDoc} */
  public OCSPCertificateVerifier(X509Certificate certificate, X509Certificate issuer,
    PropertyChangeListener... propertyChangeListeners) {
    super(certificate, issuer, EVENT_ID, propertyChangeListeners);
    this.ocspDataLoader = this;
  }

  /** {@inheritDoc} */
  @Override public ValidationStatus checkValidity() {
    return checkValidity(new Date());
  }

  /**
   * Check validity based on a specific validation date
   * @param validationDate validation date
   * @return validation status
   */
  public ValidationStatus checkValidity(Date validationDate) {
    ValidationStatus status = ValidationStatus.builder()
      .certificate(certificate)
      .issuer(issuer)
      .validationTime(validationDate)
      .sourceType(ValidatorSourceType.OCSP)
      .validity(CertificateValidity.UNKNOWN)
      .build();

    try {
      Principal subject = certificate.getSubjectX500Principal();

      String ocspUrl = CertUtils.getOCSPUrl(certificate);
      if (ocspUrl == null) {
        log.debug("OCSP URL for '{}' is empty" , subject);
        status.setStatusSignatureValid(false);
        return status;
      }

      status.setValdationSourceLocation(ocspUrl);
      log.debug("OCSP URL for '{}' is '{}'" , subject , ocspUrl);

      DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
      CertificateID certificateId = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuer),
        certificate.getSerialNumber());

      // Generate OCSP request
      byte[] nonce = getNonce();
      OCSPReq ocspReq = generateOCSPRequest(certificateId, nonce);

      // Get OCSP response from server
      OCSPResp ocspResp = ocspDataLoader.requestOCSPResponse(ocspUrl, ocspReq, connectTimeout, readTimeout);
      if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
        log.warn("OCSP response is invalid from {}", ocspUrl);
        status.setValidity(CertificateValidity.INVALID);
        status.setException(new IOException("OCSP response is invalid from" + ocspUrl + " - Status: " + RESPONSE_STATUS[ocspResp.getStatus()]));
        return status;
      }

      boolean foundResponse = false;
      BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
      checkResponseSignature(basicOCSPResp, status);

      checkNonce(basicOCSPResp, nonce);

      SingleResp[] singleResps = basicOCSPResp.getResponses();
      for (SingleResp singleResp : singleResps) {
        CertificateID responseCertificateId = singleResp.getCertID();
        if (!certificateId.equals(responseCertificateId)) {
          continue;
        }

        foundResponse = true;

        log.debug("OCSP validationDate: {}", validationDate);
        log.debug("OCSP thisUpdate: {}", singleResp.getThisUpdate());
        log.debug("OCSP nextUpdate: {}", singleResp.getNextUpdate());

        status.setRevocationObjectIssuingTime(basicOCSPResp.getProducedAt());

        Object certStatus = singleResp.getCertStatus();
        if (certStatus == CertificateStatus.GOOD) {
          log.debug("OCSP status is valid for '" + certificate.getSubjectX500Principal() + "'");
          status.setValidity(CertificateValidity.VALID);
        }
        else {
          if (singleResp.getCertStatus() instanceof RevokedStatus) {
            log.debug("OCSP status is revoked for: " + subject);
            if (validationDate.before(((RevokedStatus) singleResp.getCertStatus()).getRevocationTime())) {
              log.info("OCSP revocation time after the validation date, the certificate '" + subject + "' was valid at " + validationDate);
              status.setValidity(CertificateValidity.VALID);
            }
            else {
              RevokedStatus revokedStatus = (RevokedStatus) singleResp.getCertStatus();
              Date revocationDate = revokedStatus.getRevocationTime();
              log.debug("OCSP for certificate '{}' is revoked since {}", subject, revocationDate);
              status.setRevocationTime(revocationDate);
              status.setRevocationObjectIssuingTime(singleResp.getThisUpdate());
              status.setReason(revokedStatus.getRevocationReason());
              status.setValidity(CertificateValidity.REVOKED);
            }
          }
        }
      }

      if (!foundResponse) {
        log.debug("There are no matching OCSP response entries");
        status.setException(new IOException("There are no matching OCSP response entries"));
      }
    }
    catch (Exception ex) {
      log.warn("OCSP exception: " + ex.getMessage());
      status.setException(ex);
    }

    return status;
  }

  /**
   * Checks the nonce received in a OCSP response against the nonce sent in the request
   * @param basicOCSPResp OCSP response
   * @param nonce nonce sent in the request
   * @throws IOException if nonce validation fails
   */
  private void checkNonce(BasicOCSPResp basicOCSPResp, byte[] nonce) throws IOException {
    Extension nonceExtension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    if (nonceExtension == null){
      // OCSP responders are not required to provide nonce in the response. Absent response is therefore allowed here.
      return;
    }
    // There is a nonce in the response. Now this must match the request
    if (nonce == null){
      throw new IOException("There is a nonce in the response but no nonce was sent in the request");
    }
    byte[] responseNonce = nonceExtension.getExtnValue().getOctets();
    if (responseNonce == null || responseNonce.length > 1024){
      throw new IOException("Response nonce has illegal content");
    }
    if (Arrays.equals(nonce, responseNonce)){
      return;
    }
    throw new IOException("Nonce in request does not match nonce provided in the response");
  }

  /**
   * Generate a new nonce value if configuration activated nonce
   * @return nonce or null if no nonce is to be included
   */
  private byte[] getNonce() {
    if (!includeNonce) {
      return null;
    }
    byte[] nonceBytes = new byte[20];
    RNG.nextBytes(nonceBytes);
    return nonceBytes;
  }

  /**
   * Checks the OCSP response signature value
   * @param basicOCSPResp OCSP response
   * @param status the validation status for this OCSP response
   * @throws CertificateException error parsing certificates
   */
  private void checkResponseSignature(BasicOCSPResp basicOCSPResp, ValidationStatus status)
    throws CertificateException {
    X509CertificateHolder[] responeCerts = basicOCSPResp.getCerts();
    List<X509Certificate> certList = CertUtils.getCertificateList(responeCerts);
    if (certList.isEmpty()) {
      certList.add(issuer);
    }

    for (X509Certificate cert : certList) {
      try {
        // Attempt validation with all certs
        if (basicOCSPResp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(cert))) {
          status.setStatusSignerCertificate(cert);
          status.setStatusSignerCertificateChain(certList);
          status.setStatusSignatureValid(true);
          log.debug("Attempt to use the certificate from {} to verify OCSP response succeeded", cert.getSubjectDN());
        }
      } catch (OperatorCreationException | OCSPException ex){
        log.debug("Attempt to use the certificate from {} to verify OCSP response failed", cert.getSubjectDN());
      }
    }
  }

  /**
   * Create OCSP request
   * @param certificateId certID according to OCSP
   * @return OCSP response
   * @throws OCSPException error creating the OCSP response
   */
  protected OCSPReq generateOCSPRequest(CertificateID certificateId, byte[] nonce) throws OCSPException {
    OCSPReqBuilder ocspReqGenerator = new OCSPReqBuilder();
    Extensions extensions = (nonce == null)
      ? null
      : new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce));
    ocspReqGenerator.addRequest(certificateId);
    ocspReqGenerator.setRequestExtensions(extensions);
    return ocspReqGenerator.build();
  }

  @Override
  public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException {
    byte[] ocspReqData = ocspReq.getEncoded();

    HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
    try {
      con.setRequestProperty("Content-Type", "application/ocsp-request");
      con.setRequestProperty("Accept", "application/ocsp-response");
      con.setConnectTimeout(connectTimeout);
      con.setReadTimeout(readTimeout);

      con.setDoInput(true);
      con.setDoOutput(true);
      con.setUseCaches(false);

      OutputStream out = con.getOutputStream();
      try {
        IOUtils.write(ocspReqData, out);
        out.flush();
      }
      finally {
        IOUtils.close(out);
      }

      byte[] responseBytes = IOUtils.toByteArray(con);

      OCSPResp ocspResp = new OCSPResp(responseBytes);

      return ocspResp;
    }
    finally {
      if (con != null) {
        con.disconnect();
      }
    }
  }

}