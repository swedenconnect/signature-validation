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

package se.idsec.sigval.cert.extensions;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extensions;
import se.idsec.sigval.cert.extensions.data.AuthnContextPrefixMapper;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * AuthnContext X.509 extension implementation for extending Bouncycastle
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class AuthnContext extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.752.201.5.1");
    public static final String CONTENT_TYPE = "http://id.elegnamnden.se/auth-cont/1.0/saci";
    @Getter private List<SAMLAuthContext> statementInfoList = new ArrayList<>();


    /**
     * Creates an instance of the Authentication context extension
     *
     * @param obj object holding extension data
     * @return Authentication context extension
     */
    public static AuthnContext getInstance(Object obj) {
        if (obj instanceof AuthnContext) {
            return (AuthnContext) obj;
        }
        if (obj != null) {
            return new AuthnContext(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Creates an instance of the Authentication context extension
     *
     * @param extensions Authentication context extension
     * @return Authentication context extension
     */
    public static AuthnContext fromExtensions(Extensions extensions) {
        return AuthnContext.getInstance(extensions.getExtensionParsedValue(OID));
    }

    /**
     * Internal constructor
     *
     * Parse the content of ASN1 sequence to populate set values
     *
     * @param seq ASN1 sequence
     */
    private AuthnContext(ASN1Sequence seq) {
        this.statementInfoList = new ArrayList<>();
        try {
            for (int i = 0; i < seq.size(); i++) {
                ASN1Sequence contSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
                DERUTF8String contextType = DERUTF8String.getInstance(contSeq.getObjectAt(0));
                DERUTF8String contextInfo = DERUTF8String.getInstance(contSeq.getObjectAt(1));
                SAMLAuthContext samlAuthContext = getAuthnContext(contextInfo.getString());
                if (contextType.getString().equalsIgnoreCase(CONTENT_TYPE)) {
                    statementInfoList.add(samlAuthContext);
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad extension content");
        }
    }

    /**
     * Constructor
     *
     * @param statementInfoList list of statement infos
     */
    public AuthnContext(List<SAMLAuthContext> statementInfoList) {
        this.statementInfoList = statementInfoList;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * AuthenticationContexts ::= SEQUENCE SIZE (1..MAX) OF
     *                            AuthenticationContext
     *
     * AuthenticationContext ::= SEQUENCE {
     *     contextType     UTF8String,
     *     contextInfo     UTF8String OPTIONAL
     * }
     * </pre>
     *
     * @return
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector authnConexts = new ASN1EncodableVector();

        for (SAMLAuthContext statementInfo : statementInfoList) {
            ASN1EncodableVector authnConext = new ASN1EncodableVector();
            try {
                authnConext.add(new DERUTF8String(CONTENT_TYPE));
                String contextXML = printAuthnContext(statementInfo, false);
                authnConext.add(new DERUTF8String(contextXML));
                authnConexts.add(new DERSequence(authnConext));
            } catch (Exception ex) {
                Logger.getLogger(AuthnContext.class.getName()).warning(ex.getMessage());
            }
        }
        return new DERSequence(authnConexts);
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        //b.append("AuthenticationContext [\n");
        for (SAMLAuthContext statementInfo : statementInfoList) {
            b.append(" SAML Authentication Context Info (http://id.elegnamnden.se/auth-cont/1.0/saci):\n");
            try {
                b.append(printAuthnContext(statementInfo, true)).append("\n");
            } catch (JAXBException ex) {
                b.append("Bad XML content: ").append(ex.getMessage()).append("\n");
            }
        }
        return b.toString();
    }

    /**
     * Creates a {@link SAMLAuthContext} object from an xml string
     * @param xml xml string
     * @return {@link SAMLAuthContext} object
     * @throws JAXBException on error parsing data
     */
    public static SAMLAuthContext getAuthnContext(String xml) throws JAXBException {
        return (SAMLAuthContext) getAuthnContextJAXBContext()
          .createUnmarshaller()
          .unmarshal(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Converts a {@link SAMLAuthContext} object to XML string
     *
     * @param authnConext {@link SAMLAuthContext} object
     * @param formatted true to generate pretty printing version
     * @return XML string
     * @throws JAXBException on error parsing data
     */
    public static String printAuthnContext(SAMLAuthContext authnConext, boolean formatted) throws JAXBException {
        Marshaller marshaller = getAuthnContextJAXBContext().createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        try {
            marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", new AuthnContextPrefixMapper());
        } catch (Exception ex){
            log.warn("Unable to set the com.sun.xml.bind.namespacePrefixMapper property");
        }
        if (formatted){
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        }
        StringWriter stringWriter = new StringWriter();
        marshaller.marshal(authnConext, stringWriter);
        return stringWriter.toString();
    }

    /**
     * Creates JAXB context for the {@link SAMLAuthContext} class
     *
     * @return JAXB context
     * @throws JAXBException on error creating context
     */
    private static JAXBContext getAuthnContextJAXBContext() throws JAXBException {
        return JAXBContext.newInstance(
          "se.swedenconnect.schemas.cert.authcont.saci_1_0",
          AuthnContext.class.getClassLoader()
        );
    }


}
