package se.swedenconnect.sigval.jose.jades;

import lombok.Data;

import java.util.List;

/**
 * Data structure for the ETSI JAdES etsiU unprotected header claim.
 * The etsiU claim may contain a large number of different data components.
 * This class limits the number of specified components to the ones that are relevant for
 * simple validation and for issuance of SVT.
 *
 * For this purpose, only the "sigTst" component that carries signature timestamps, is specified.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
public class EtsiUComponent {

  /** The signature timestamp component of an etsiU claim */
  private TimeStampData sigTst;

  /**
   * Data content of the sigTst component
   */
  @Data
  public static class TimeStampData {

    /** List of time stamp tokens */
    List<TimeStampToken> tstTokens;
  }

  /**
   * Data content of time stamp tokens
   */
  @Data
  public static class TimeStampToken {

    /** The string value of the time stamp token, holding a Bas64 encoded time RFC 3161 timestamp */
    String val;
  }
}
