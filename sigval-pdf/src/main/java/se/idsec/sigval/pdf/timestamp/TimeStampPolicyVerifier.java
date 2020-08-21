package se.idsec.sigval.pdf.timestamp;

import org.bouncycastle.asn1.tsp.TSTInfo;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;

import java.security.cert.X509Certificate;
import java.util.List;

public interface TimeStampPolicyVerifier {
  PolicyValidationClaims verifyTsPolicy(byte[] pdfSigBytes, TSTInfo tstInfo, X509Certificate sigCert, List<X509Certificate> certList);
}
