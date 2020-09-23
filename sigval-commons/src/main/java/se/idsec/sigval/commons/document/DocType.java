/*
 * Copyright 2017 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package se.idsec.sigval.commons.document;

import lombok.AllArgsConstructor;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Enumeration of document types
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
public enum DocType {
    XML,PDF,ASICS_NON_ETSI, ASICS_S, ASICS_CADES, CADES, UNKNOWN;

    /**
     * Determine the document type
     *
     * @param document A document
     * @return the document type or UNKNOWN if document type could not be determined
     */
    public static DocType getDocType(byte[] document) {
        return getDocType(new ByteArrayInputStream(document));
    }

    /**
     * Determine the document type of an input stream
     *
     * @param is An InputStream holding the document
     * @return the document type or UNKNOWN if document type could not be determined
     */
    public static DocType getDocType(InputStream is) {
        InputStream input = null;

        try {
            input = new BufferedInputStream(is);
            input.mark(5);
            byte[] preamble = new byte[5];
            int read = 0;
            try {
                read = input.read(preamble);
                input.reset();
            } catch (IOException ex) {
                return DocType.UNKNOWN;
            }
            if (read < 5) {
                return DocType.UNKNOWN;
            }
            String preambleString = new String(preamble);
            byte[] xmlPreable = new byte[]{'<', '?', 'x', 'm', 'l'};
            byte[] xmlUtf8 = new byte[]{-17, -69, -65, '<', '?'};
            if (Arrays.equals(preamble, xmlPreable) || Arrays.equals(preamble, xmlUtf8)) {
                return DocType.XML;
            } else if (preambleString.equals("%PDF-")) {
                return DocType.PDF;
            } else if (preamble[0] == 'P' && preamble[1] == 'K') {
                ZipInputStream asics = new ZipInputStream(new BufferedInputStream(is));
                ByteArrayOutputStream datafile = null;
                ByteArrayOutputStream signatures = null;
                ZipEntry entry;
                try {
                    while ((entry = asics.getNextEntry()) != null) {
                        if (entry.getName().equals("META-INF/signatures.p7s")) {
                            signatures = new ByteArrayOutputStream();
                            IOUtils.copy(asics, signatures);
                            signatures.close();
                        } else if (entry.getName().equalsIgnoreCase("META-INF/signatures.p7s")) {
                            /* Wrong case */
                            return DocType.ASICS_NON_ETSI;
                        } else if (entry.getName().indexOf("/") == -1) {
                            if (datafile == null) {
                                datafile = new ByteArrayOutputStream();
                                IOUtils.copy(asics, datafile);
                                datafile.close();
                            } else {
                                return DocType.ASICS_S;
                            }
                        }
                    }
                } catch (Exception ex) {
                    return DocType.UNKNOWN;
                }
                if (datafile == null || signatures == null) {
                    return DocType.UNKNOWN;
                }
                return DocType.ASICS_CADES;

            } else if (preambleString.getBytes()[0] == 0x30) {
                return DocType.CADES;
            } else {
                return DocType.UNKNOWN;
            }
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                }
            }
        }
    }
}
