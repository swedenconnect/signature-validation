/*
 * Copyright (c) 2020-2022.  Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.sigval.jose.svt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;
import se.swedenconnect.sigval.jose.verify.JOSESignedDocumentValidator;
import se.swedenconnect.sigval.svt.issuer.SVTModel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements functions to issue SVT for a JOSE signature and to extend the signatures of the JOSE signature with SVT tokens
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class JOSEDocumentSVTIssuer {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final JOSESVTSigValClaimsIssuer svtClaimsIssuer;

  public JOSEDocumentSVTIssuer(JOSESVTSigValClaimsIssuer svtClaimsIssuer) {
    this.svtClaimsIssuer = svtClaimsIssuer;
  }

  /**
   * Issues Signature Validation Tokens to signatures of a JOSE signature document and extends the signatures with SVT tokens.
   * @param document The signed document to extend
   * @param svtModel model providing basic SVT parameters
   * @param svtMethod specifying the extension strategy as defined by options declared in {@link SVTExtendpolicy}
   * @return bytes of signed XML document extended with SVT
   * @throws Exception on critical errors that prevents the document from being extended as requested
   */
  public byte[] issueSvt(byte[] document, SVTModel svtModel, SVTExtendpolicy svtMethod) throws Exception {
    return issueSvt(document, svtModel, svtMethod, null);
  }

  /**
   * Issues Signature Validation Tokens to signatures of an XML document and extends the document signatures with the SVT tokens.
   * @param document The signed document to extend
   * @param svtModel model providing basic SVT parameters
   * @param svtMethod specifying the extension strategy as defined by options declared in {@link SVTExtendpolicy}
   * @param detatchedPayload optional detached payload or null if the payload is embedded in the JOSE signature
   * @return bytes of signed XML document extended with SVT
   * @throws Exception on critical errors that prevents the document from being extended as requested
   */
  public byte[] issueSvt(byte[] document, SVTModel svtModel, SVTExtendpolicy svtMethod, Payload detatchedPayload) throws Exception {

    final List<JOSESignatureData> signatureDataList = JOSESignedDocumentValidator.getJOSEDocumentSignatureData(document, detatchedPayload);

    // Verify all signatures ...
    //
    List<SVTExtensionData> svtExtensionDataList = new ArrayList<>();
    for (JOSESignatureData signatureData : signatureDataList) {
      SignedJWT signedSvtJWT;
      SVTExtensionData svtExtensionData = new SVTExtensionData(null, signatureData, null);
      try {
        signedSvtJWT = svtClaimsIssuer.getSignedSvtJWT(
          JOSESVTValInput.builder()
            .signatureData(signatureData)
            .svtExtendpolicy(svtMethod)
            .build(), svtModel
        );
        if (signedSvtJWT != null) {
          svtExtensionData = new SVTExtensionData(signedSvtJWT, signatureData, svtMethod);
        }
      }
      catch (Exception ex) {
        log.error("Signature validation claims collection caused error: {}", ex.getMessage(), ex);
      }
      svtExtensionDataList.add(svtExtensionData);
    }
    return extendDocumentSignature(document, svtExtensionDataList);
  }

  /**
   * Extends the document signature with SVT token
   * @param svtExtensionDataList
   * @return
   * @throws Exception
   */
  private byte[] extendDocumentSignature(byte[] document, List<SVTExtensionData> svtExtensionDataList) throws Exception{

    if (svtExtensionDataList.isEmpty()){
      // Nothing to do
      log.debug("No SVT tokens to add");
      return document;
    }

    if (svtExtensionDataList.size() == 1){
      JSONFlattenedSerializedDocument flattenedJoseDoc = new JSONFlattenedSerializedDocument();
      SVTExtensionData svtExtensionData = svtExtensionDataList.get(0);
      final JOSESignatureData signatureData = svtExtensionData.getSignatureData();
      flattenedJoseDoc.setSignature(Base64URL.encode(signatureData.getSignatureBytes()).toString());
      flattenedJoseDoc.setPayload(signatureData.isDetached() ? "" : signatureData.getPayload().toBase64URL().toString());
      flattenedJoseDoc.setProtectedHeader(signatureData.getHeader().toBase64URL().toString());
      flattenedJoseDoc.setUnprotectedHeader(extendUnprotectedHeader(svtExtensionData));
      return OBJECT_MAPPER.writeValueAsBytes(flattenedJoseDoc);
    }


    boolean detached = svtExtensionDataList.get(0).getSignatureData().isDetached();
    String payloadStr = detached
      ? ""
      : svtExtensionDataList.get(0).getSignatureData().getPayload().toBase64URL().toString();
    List<JSONSerializedDocument.JOSESignature> signatureList = new ArrayList<>();

    for (SVTExtensionData svtExtensionData:svtExtensionDataList) {
      final JOSESignatureData signatureData = svtExtensionData.getSignatureData();
      JSONSerializedDocument.JOSESignature joseSignature = new JSONSerializedDocument.JOSESignature();
      joseSignature.setSignature(Base64URL.encode(signatureData.getSignatureBytes()).toString());
      joseSignature.setProtectedHeader(signatureData.getHeader().toBase64URL().toString());
      joseSignature.setUnprotectedHeader(extendUnprotectedHeader(svtExtensionData));
      signatureList.add(joseSignature);
    }
    JSONSerializedDocument jsonSerializedDocument = new JSONSerializedDocument(payloadStr, signatureList);
    return OBJECT_MAPPER.writeValueAsBytes(jsonSerializedDocument);

  }

  private Map<String, Object> extendUnprotectedHeader(SVTExtensionData svtExtensionData) {

    final JOSESignatureData signatureData = svtExtensionData.getSignatureData();
    final SignedJWT signedJWT = svtExtensionData.getSignedJWT();
    final SVTExtendpolicy svtMethod = svtExtensionData.getSvtMethod();

    final Map<String, Object> unprotectedHeaders = signatureData.getUnprotectedHeader() == null
      ? new HashMap<>()
      : new HashMap<>(signatureData.getUnprotectedHeader().toJSONObject());

    if (signedJWT == null){
      // Nothing to do. return input value or null if map is empty
      return unprotectedHeaders.isEmpty() ? null : unprotectedHeaders;
    }

    // Check for existing svt
    List<String> base64URLSVTList = new ArrayList<>();
    if (unprotectedHeaders.containsKey("svt")){
      final Object svtHeaderObj = unprotectedHeaders.get("svt");

      try {
        base64URLSVTList = new ArrayList<>(OBJECT_MAPPER.readValue(
          OBJECT_MAPPER.writeValueAsString(svtHeaderObj),
          new TypeReference<>() {}));
      }
      catch (JsonProcessingException e) {
        log.debug("Unable to parse existing SVT tokens");
      }

      switch (svtMethod){
      case EXTEND:
        base64URLSVTList.add(signedJWT.serialize());
        break;
      case REPLACE:
        base64URLSVTList = List.of(signedJWT.serialize());
      }

    } else {
      // There is no prior svt. Create new svt claim
      base64URLSVTList.add(signedJWT.serialize());
    }
    if (!base64URLSVTList.isEmpty()){
      unprotectedHeaders.put("svt", base64URLSVTList);
    }

    return unprotectedHeaders;
  }

  @Data
  @AllArgsConstructor
  private class SVTExtensionData {

    private SignedJWT signedJWT;
    private JOSESignatureData signatureData;
    private SVTExtendpolicy svtMethod;

  }

}
