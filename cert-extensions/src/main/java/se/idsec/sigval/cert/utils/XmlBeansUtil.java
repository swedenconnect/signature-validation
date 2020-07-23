/*
 * Copyright (c) 2020. IDsec Solutions AB
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
package se.idsec.sigval.cert.utils;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.w3c.dom.Document;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for XML objects instantiated using XMLBeans
 *
 * @TODO Consider migration to JAXB
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class XmlBeansUtil {

    private static final Map<String, String> prefixMap = new HashMap<String, String>();
    public static final XmlOptions styled;
    public static final XmlOptions styledNoHeader;
    public static final XmlOptions noHeader;
    public static final XmlOptions stripWhiteSPcae;
    public static final XmlOptions canonical;
    public static final XmlOptions schemaValid;

    static {
        prefixMap.put("urn:se:tillvaxtverket:tsltrust:1.0:sigval:report", "tslt");
        prefixMap.put("http://www.w3.org/2000/09/xmldsig#", "ds");
        prefixMap.put("http://www.w3.org/2001/04/xmlenc#", "xenc");
        prefixMap.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");
        prefixMap.put("urn:oasis:names:tc:SAML:1.0:assertion", "saml1");
        prefixMap.put("urn:oasis:names:tc:SAML:2.0:protocol", "samlp");
        prefixMap.put("http://www.w3.org/2001/XMLSchema", "xs");
        prefixMap.put("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        prefixMap.put("http://id.elegnamnden.se/csig/1.0/dss-ext/ns", "eid2");
        prefixMap.put("urn:oasis:names:tc:dss:1.0:core:schema", "dss");
        prefixMap.put("http://id.elegnamnden.se/auth-cont/1.0/saml", "saci");
        prefixMap.put("urn:oasis:names:tc:SAML:2.0:metadata", "md");
        prefixMap.put("urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol", "idpdisco");
        prefixMap.put("urn:oasis:names:tc:SAML:profiles:SSO:request-init", "init");
        prefixMap.put("urn:oasis:names:tc:SAML:metadata:attribute", "mdattr");
        prefixMap.put("urn:oasis:names:tc:SAML:metadata:ui", "mdui");
        prefixMap.put("http://uri.etsi.org/01903/v1.3.2#", "xades");
        prefixMap.put("http://id.elegnamnden.se/csig/1.1/sap/ns", "sap");

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

        canonical = new XmlOptions().setSavePrettyPrintIndent(0).setSaveNoXmlDecl().setSaveSuggestedPrefixes(prefixMap);
        canonical.setSaveCDataLengthThreshold(10000);
        canonical.setSaveCDataEntityCountThreshold(50);
        
        schemaValid = new XmlOptions().setSavePrettyPrintIndent(0).setSaveNoXmlDecl().setSaveSuggestedPrefixes(prefixMap);
        schemaValid.setSaveAggressiveNamespaces();
        schemaValid.setSaveCDataLengthThreshold(10000);
        schemaValid.setSaveCDataEntityCountThreshold(50);

    }

    public static String getStyledText(Document doc) {
        return new String(getStyledBytes(doc), Charset.forName("UTF-8"));
    }
    public static byte[] getStyledBytes(Document doc) {
        try {
            return getStyledBytes(XmlObject.Factory.parse(doc));
        } catch (XmlException ex) {
            return new byte[]{};
        }
    }
    public static byte[] getStyledBytes(XmlObject xo) {
        return getStyledBytes(xo, true);
    }

    public static byte[] getStyledBytes(XmlObject xo, boolean xmlHeader) {
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (xmlHeader) {
                xo.save(bos, styled);
            } else {
                xo.save(bos, styledNoHeader);
            }
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    public static byte[] getBytes(XmlObject xo) {
        return getBytes(xo, true);
    }

    public static byte[] getBytes(XmlObject xo, boolean xmlHeader) {
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (xmlHeader) {
                xo.save(bos);
            } else {
                xo.save(bos, noHeader);
            }
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    public static byte[] getCanonicalBytes(XmlObject xo) {
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            xo.save(bos, canonical);
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }
    
    public static byte[] getSchemaValid(XmlObject xo){
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            xo.save(bos, schemaValid);
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;        
    }
}
