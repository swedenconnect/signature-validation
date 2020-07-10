package se.idsec.sigval.cert.validity.crl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CRLCacheRecord {

  private long lastCache;
  private long nextUpdate;
  private String url;
  private String fileName;
}
