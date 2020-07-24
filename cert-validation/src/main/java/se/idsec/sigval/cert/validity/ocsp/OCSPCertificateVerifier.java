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

package se.idsec.sigval.cert.validity.ocsp;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import se.idsec.sigval.cert.utils.CertUtils;
import se.idsec.sigval.cert.validity.AbstractValidityChecker;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.ValidationStatus.CertificateValidity;
import se.idsec.sigval.cert.validity.ValidationStatus.ValidatorSourceType;

import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Certificate verifier based on OCSP
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class OCSPCertificateVerifier extends AbstractValidityChecker {

  public static final String EVENT_ID = "ocsp-validity";
  public static final String[] RESPONSE_STATUS = new String[]{
    "SUCCESSFUL",
    "MALFORMED_REQUEST",
    "INTERNAL_ERROR",
    "TRY_LATER",
    "NO_USED",
    "SIG_REQUIRED",
    "UNAUTHORIZED"
  };

  public OCSPCertificateVerifier(X509Certificate certificate, X509Certificate issuer,
    PropertyChangeListener... propertyChangeListeners) {
    super(certificate, issuer, EVENT_ID, propertyChangeListeners);
  }

  @Override public ValidationStatus checkValidity() {
    return checkValidity(new Date());
  }

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
      OCSPReq ocspReq = generateOCSPRequest(certificateId);

      // Get OCSP response from server
      OCSPResp ocspResp = requestOCSPResponse(ocspUrl, ocspReq);
      if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
        log.warn("OCSP response is invalid from {}", ocspUrl);
        status.setValidity(CertificateValidity.INVALID);
        status.setException(new IOException("OCSP response is invalid from" + ocspUrl + " - Status: " + RESPONSE_STATUS[ocspResp.getStatus()]));
        return status;
      }

      boolean foundResponse = false;
      BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
      checkResponseSignature(basicOCSPResp, status);

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
              Date revocationDate = ((RevokedStatus) singleResp.getCertStatus()).getRevocationTime();
              log.debug("OCSP for certificate '{}' is revoked since {}", subject, revocationDate);
              status.setRevocationTime(revocationDate);
              status.setRevocationObjectIssuingTime(singleResp.getThisUpdate());
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

  private void checkResponseSignature(BasicOCSPResp basicOCSPResp, ValidationStatus status) throws OperatorCreationException, OCSPException,
    CertificateException {
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
      } catch (Exception ex){
        log.debug("Attempt to use the certificate from {} to verify OCSP response failed", cert.getSubjectDN());
      }
    }
  }

  private OCSPReq generateOCSPRequest(CertificateID certificateId) throws OCSPException {
    OCSPReqBuilder ocspReqGenerator = new OCSPReqBuilder();

    ocspReqGenerator.addRequest(certificateId);

    OCSPReq ocspReq = ocspReqGenerator.build();
    return ocspReq;
  }

  public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq) throws IOException {
    byte[] ocspReqData = ocspReq.getEncoded();

    HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
    try {
      con.setRequestProperty("Content-Type", "application/ocsp-request");
      con.setRequestProperty("Accept", "application/ocsp-response");
      con.setConnectTimeout(1000);
      con.setReadTimeout(3000);

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