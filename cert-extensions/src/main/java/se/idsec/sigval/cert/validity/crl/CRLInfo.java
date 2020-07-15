package se.idsec.sigval.cert.validity.crl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509CRL;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CRLInfo {

  private String location;
  private X509CRL crl;

}
