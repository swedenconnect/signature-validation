package se.swedenconnect.sigval.jose.svt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonPropertyOrder({"payload", "signatures" })
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JSONSerializedDocument {

  private String payload;
  private List<JOSESignature> signatures;


  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @JsonPropertyOrder({"protected","header", "signature" })
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class JOSESignature {

    @JsonProperty("protected")
    private String protectedHeader;

    @JsonProperty("header")
    private Map<String, Object> unprotectedHeader;

    private String signature;
  }

}
