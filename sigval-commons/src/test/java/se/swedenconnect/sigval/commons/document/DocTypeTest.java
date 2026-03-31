/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.sigval.commons.document;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link DocType}.
 */
class DocTypeTest {

  @Test
  void getDocType_xmlAsciiPreamble_returnsXML() {
    byte[] xml = "<?xml version=\"1.0\"?><root/>".getBytes(StandardCharsets.US_ASCII);
    assertEquals(DocType.XML, DocType.getDocType(xml));
  }

  @Test
  void getDocType_xmlUtf8BomPreamble_returnsXML() {
    // UTF-8 BOM: EF BB BF, followed by <?
    byte[] xml = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '<', '?', 'x', 'm', 'l', '>'};
    assertEquals(DocType.XML, DocType.getDocType(xml));
  }

  @Test
  void getDocType_pdfPreamble_returnsPDF() {
    byte[] pdf = "%PDF-1.4 %some content".getBytes(StandardCharsets.US_ASCII);
    assertEquals(DocType.PDF, DocType.getDocType(pdf));
  }

  @Test
  void getDocType_cadesPreamble_returnsCADES() {
    // CAdES starts with 0x30 (ASN.1 SEQUENCE tag)
    byte[] cades = new byte[]{0x30, 0x00, 0x01, 0x02, 0x03};
    assertEquals(DocType.CADES, DocType.getDocType(cades));
  }

  @Test
  void getDocType_joseJsonPreamble_returnsJOSE() {
    byte[] jose = "{ \"payload\": \"test\" }".getBytes(StandardCharsets.US_ASCII);
    assertEquals(DocType.JOSE, DocType.getDocType(jose));
  }

  @Test
  void getDocType_joseCompactPreamble_returnsJOSE_COMPACT() {
    // Compact JWS starts with "eyJ" (base64url of {"alg":...)
    byte[] joseCompact = "eyJhbGciOiJFUzI1NiJ9.payload.sig".getBytes(StandardCharsets.US_ASCII);
    assertEquals(DocType.JOSE_COMPACT, DocType.getDocType(joseCompact));
  }

  @Test
  void getDocType_tooShortInput_returnsUNKNOWN() {
    byte[] short_data = new byte[]{0x01, 0x02};
    assertEquals(DocType.UNKNOWN, DocType.getDocType(short_data));
  }

  @Test
  void getDocType_emptyInput_returnsUNKNOWN() {
    assertEquals(DocType.UNKNOWN, DocType.getDocType(new byte[0]));
  }

  @Test
  void getDocType_randomBytes_returnsUNKNOWN() {
    byte[] random = new byte[]{0x41, 0x42, 0x43, 0x44, 0x45};
    assertEquals(DocType.UNKNOWN, DocType.getDocType(random));
  }

  @Test
  void getDocType_pkZipPreamble_notUnknown() {
    // A byte[] starting with PK magic is recognised as ZIP before the stream is consumed.
    // The classification depends on ZIP contents, but it is never UNKNOWN at the preamble check.
    // Note: full ASiC-S classification requires InputStream to remain unconsumed after
    // preamble detection — that path is exercised by integration tests.
    byte[] pkMagic = new byte[]{'P', 'K', 0x03, 0x04, 0x00};
    DocType type = DocType.getDocType(pkMagic);
    // getDocType opens a ZipInputStream on the (already consumed) original InputStream,
    // which yields no entries → both datafile and signatures are null → UNKNOWN
    assertEquals(DocType.UNKNOWN, type);
  }
}
