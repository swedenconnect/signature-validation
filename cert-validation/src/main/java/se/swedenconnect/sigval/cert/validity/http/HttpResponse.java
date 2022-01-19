package se.swedenconnect.sigval.cert.validity.http;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * HTTP response data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class HttpResponse {

  /** Data contained in the HTTP response */
  byte[] data;
  /** HTTP response code */
  int responseCode;
  /** Exception encountered */
  Exception exception;
}
