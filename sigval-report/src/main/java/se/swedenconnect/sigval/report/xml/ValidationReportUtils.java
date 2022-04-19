/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.report.xml;

import lombok.extern.slf4j.Slf4j;
import org.apache.xmlbeans.XmlOptions;
import org.etsi.uri.x19102.v12.ValidationReportDocument;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class ValidationReportUtils {

  private static final Map<String, String> prefixMap = new HashMap<String, String>();
  public static final XmlOptions styled;
  public static final XmlOptions styledNoHeader;
  public static final XmlOptions noHeader;
  public static final XmlOptions stripWhiteSPcae;
  public static final XmlOptions canonical;

  static {
    prefixMap.put("urn:se:tillvaxtverket:tsltrust:1.0:sigval:report", "tslt");
    prefixMap.put("http://www.w3.org/2000/09/xmldsig#", "ds");
    prefixMap.put("http://uri.etsi.org/19102/v1.2.1#", "svr");
    prefixMap.put("http://uri.etsi.org/01903/v1.3.2#", "xades");
    prefixMap.put("http://uri.etsi.org/02231/v2#", "tsl");
    prefixMap.put("http://www.w3.org/2001/XMLSchema", "xs");
    prefixMap.put("http://www.w3.org/2001/XMLSchema-instance", "xsi");
    prefixMap.put("http://id.elegnamnden.se/auth-cont/1.0/saci", "saci");
    prefixMap.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");

    styled = new XmlOptions().setSavePrettyPrint().setSavePrettyPrintIndent(4);
    styled.setSaveSuggestedPrefixes(prefixMap);
    styled.setSaveCDataLengthThreshold(10000);
    styled.setSaveCDataEntityCountThreshold(50);

    styledNoHeader = new XmlOptions().setSavePrettyPrint().setSavePrettyPrintIndent(4);
    styledNoHeader.setSaveSuggestedPrefixes(prefixMap);
    styledNoHeader.setSaveCDataLengthThreshold(10000);
    styledNoHeader.setSaveCDataEntityCountThreshold(50);
    styledNoHeader.setSaveNoXmlDecl();

    noHeader = new XmlOptions().setSaveNoXmlDecl();
    noHeader.setSaveSuggestedPrefixes(prefixMap);

    stripWhiteSPcae = new XmlOptions().setLoadStripWhitespace();

    canonical = new XmlOptions().setSavePrettyPrint().setSavePrettyPrintIndent(0).setSaveNoXmlDecl().setSaveSuggestedPrefixes(prefixMap);
    canonical.setSaveCDataLengthThreshold(10000);
    canonical.setSaveCDataEntityCountThreshold(50);

  }

  /**
   * Gets the XML bytes of the validation report as styled XML
   * @param validationReport validation report
   * @return validation report XML bytes
   * @throws IOException on errors converting the validation report to XML
   */
  public static byte[] getReportXml(ValidationReportDocument validationReport) throws IOException {
    return getReportXml(validationReport, styled);
  }

  /**
   * Gets the XML bytes of the validation report
   * @param validationReport validation report
   * @param style style
   * @return validation report XML bytes
   * @throws IOException on errors converting the validation report to XML
   */
  public static byte[] getReportXml(ValidationReportDocument validationReport, XmlOptions style) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    validationReport.save(bos, style);
    byte[] result = bos.toByteArray();
    bos.close();
    return result;
  }
}
