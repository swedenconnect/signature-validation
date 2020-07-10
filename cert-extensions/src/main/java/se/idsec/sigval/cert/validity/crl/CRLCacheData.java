package se.idsec.sigval.cert.validity.crl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CRLCacheData {
  List<CRLCacheRecord> crlCacheRecordList;
}
