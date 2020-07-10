/*
 * Software in this class is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package se.idsec.sigval.cert.validity.ocsp;

import lombok.extern.java.Log;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import se.idsec.sigval.cert.utils.CertUtils;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.ValidationStatus.CertificateValidity;
import se.idsec.sigval.cert.validity.ValidationStatus.ValidatorSourceType;
import se.idsec.sigval.cert.validity.ValidityChecker;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Certificate verifier based on OCSP
 *
 * @author Stefan Santesson
 */
@Log
public class OCSPCertificateVerifier implements ValidityChecker {

  List<PropertyChangeListener> listeners;
  X509Certificate certificate;
  X509Certificate issuer;

  public OCSPCertificateVerifier(X509Certificate certificate, X509Certificate issuer, PropertyChangeListener... propertyChangeListeners) {
    this.certificate = certificate;
    this.issuer = issuer;
    this.listeners = Arrays.asList(propertyChangeListeners);
  }

  @Override public void run() {
    ValidationStatus validationStatus = checkValidity();
    PropertyChangeEvent event = new PropertyChangeEvent(this, "ocsp-validity", null, validationStatus);
    listeners.stream().forEach(propertyChangeListener -> propertyChangeListener.propertyChange(event));
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
        log.warning("OCSP URL for '" + subject + "' is empty");
        return status;
      }

      status.setValdationSourceLocation(ocspUrl);
      log.fine("OCSP URL for '" + subject + "' is '" + ocspUrl + "'");

      DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
      CertificateID certificateId = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuer),
        certificate.getSerialNumber());

      // Generate OCSP request
      OCSPReq ocspReq = generateOCSPRequest(certificateId);

      // Get OCSP response from server
      OCSPResp ocspResp = requestOCSPResponse(ocspUrl, ocspReq);
      if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
        log.warning("OCSP response is invalid from " + ocspUrl);
        status.setValidity(CertificateValidity.INVALID);
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

        log.fine("OCSP validationDate: " + validationDate);
        log.fine("OCSP thisUpdate: " + singleResp.getThisUpdate());
        log.fine("OCSP nextUpdate: " + singleResp.getNextUpdate());

        status.setRevocationObjectIssuingTime(basicOCSPResp.getProducedAt());

        Object certStatus = singleResp.getCertStatus();
        if (certStatus == CertificateStatus.GOOD) {
          log.fine("OCSP status is valid for '" + certificate.getSubjectX500Principal() + "'");
          status.setValidity(CertificateValidity.VALID);
        }
        else {
          if (singleResp.getCertStatus() instanceof RevokedStatus) {
            log.fine("OCSP status is revoked for: " + subject);
            if (validationDate.before(((RevokedStatus) singleResp.getCertStatus()).getRevocationTime())) {
              log.info("OCSP revocation time after the validation date, the certificate '" + subject + "' was valid at " + validationDate);
              status.setValidity(CertificateValidity.VALID);
            }
            else {
              Date revocationDate = ((RevokedStatus) singleResp.getCertStatus()).getRevocationTime();
              log.warning("OCSP for certificate '" + subject + "' is revoked since " + revocationDate);
              status.setRevocationTime(revocationDate);
              status.setRevocationObjectIssuingTime(singleResp.getThisUpdate());
              status.setValidity(CertificateValidity.REVOKED);
            }
          }
        }
      }

      if (!foundResponse) {
        log.fine("There is no matching OCSP response entries");
      }
    }
    catch (Exception ex) {
      log.warning("OCSP exception: " + ex.getMessage());
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
      if (basicOCSPResp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(cert))) {
        status.setStatusSignerCertificate(cert);
        status.setStatusSignerCertificateChain(certList);
        status.setStatusSignatureValid(true);
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