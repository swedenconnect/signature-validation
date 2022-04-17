package se.swedenconnect.sigval.jose.svt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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
@JsonPropertyOrder({"payload", "protected","header", "signature" })
@JsonInclude(JsonInclude.Include.NON_NULL)
public class JSONFlattenedSerializedDocument {

  private String payload;
  @JsonProperty("protected")
  private String protectedHeader;

  @JsonProperty("header")
  private Map<String, Object> unprotectedHeader;

  private String signature;

}
