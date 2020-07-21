package se.idsec.sigval.cert.chain;

import lombok.*;
import se.idsec.sigval.cert.validity.ValidationStatus;

import java.security.cert.Extension;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PathValidationResult {

  private boolean validCert;
  private PKIXCertPathBuilderResult pkixCertPathBuilderResult;
  private X509Certificate targetCertificate;
  private List<X509Certificate> chain;
  private List<ValidationStatus> validationStatusList;
  private Exception exception;
}
