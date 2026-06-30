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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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
  void getDocType_truncatedZipPreamble_returnsUNKNOWN() {
    // A bare PK local-file-header signature with no complete ZIP entry. The ZIP parse fails to
    // produce any entry, so neither a data file nor a signature entry is found → UNKNOWN.
    byte[] pkMagic = new byte[]{'P', 'K', 0x03, 0x04, 0x00};
    assertEquals(DocType.UNKNOWN, DocType.getDocType(pkMagic));
  }

  @Test
  void getDocType_asicCades_returnsASICS_CADES() throws IOException {
    // One top-level data file plus the ETSI signatures entry.
    byte[] zip = buildZip(entries(
        "document.xml", 16,
        "META-INF/signatures.p7s", 16));
    assertEquals(DocType.ASICS_CADES, DocType.getDocType(zip));
  }

  @Test
  void getDocType_asicSeveralTopLevelFiles_returnsASICS_S() throws IOException {
    // A second top-level entry classifies as ASiC-S, independent of any signature entry.
    byte[] zip = buildZip(entries(
        "doc1.xml", 16,
        "doc2.xml", 16));
    assertEquals(DocType.ASICS_S, DocType.getDocType(zip));
  }

  @Test
  void getDocType_signaturesEntryWrongCase_returnsASICS_NON_ETSI() throws IOException {
    // Entry name matches the signatures entry only case-insensitively.
    byte[] zip = buildZip(entries("META-INF/Signatures.P7S", 16));
    assertEquals(DocType.ASICS_NON_ETSI, DocType.getDocType(zip));
  }

  @Test
  void getDocType_zipWithoutSignatures_returnsUNKNOWN() throws IOException {
    // A single top-level data file but no signatures entry is not a recognised ASiC type.
    byte[] zip = buildZip(entries("document.xml", 16));
    assertEquals(DocType.UNKNOWN, DocType.getDocType(zip));
  }

  /**
   * Regression guard for the zip-bomb OOM: a ZIP whose top-level entry decompresses to a large
   * payload must classify without buffering the entry body into memory.
   *
   * <p>The previous implementation copied each entry into an unbounded {@code ByteArrayOutputStream},
   * so a small zip whose entry expands to gigabytes exhausted the heap. The fix classifies on entry
   * names only and never reads the body, so memory use stays flat regardless of the decompressed
   * size. The body here is zeros, which compress to a tiny archive; to actively reproduce the
   * original {@code OutOfMemoryError} against the old code, raise {@code largeEntryBytes} well above
   * the available heap and run with a constrained {@code -Xmx}.</p>
   */
  @Test
  void getDocType_largeDecompressingEntry_doesNotExhaustHeap() throws IOException {
    final int largeEntryBytes = 64 * 1024 * 1024; // 64 MiB of zeros; compresses to a few KiB
    byte[] zip = buildZip(entries(
        "bigfile.bin", largeEntryBytes,
        "META-INF/signatures.p7s", 16));
    assertEquals(DocType.ASICS_CADES, DocType.getDocType(zip));
  }

  /**
   * Builds a DEFLATED ZIP archive in memory. Each entry is filled with the given number of zero
   * bytes (highly compressible), written in chunks so that large entries never materialise as a
   * single array.
   *
   * @param entrySizes ordered map of entry name to uncompressed byte count
   * @return the encoded ZIP archive
   */
  private static byte[] buildZip(final Map<String, Integer> entrySizes) throws IOException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    final byte[] chunk = new byte[64 * 1024];
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      for (final Map.Entry<String, Integer> e : entrySizes.entrySet()) {
        zos.putNextEntry(new ZipEntry(e.getKey()));
        int remaining = e.getValue();
        while (remaining > 0) {
          final int n = Math.min(chunk.length, remaining);
          zos.write(chunk, 0, n);
          remaining -= n;
        }
        zos.closeEntry();
      }
    }
    return baos.toByteArray();
  }

  /**
   * Builds an ordered {@code name -> size} map from alternating name/size arguments.
   */
  private static Map<String, Integer> entries(final Object... nameThenSize) {
    final Map<String, Integer> map = new LinkedHashMap<>();
    for (int i = 0; i < nameThenSize.length; i += 2) {
      map.put((String) nameThenSize[i], (Integer) nameThenSize[i + 1]);
    }
    return map;
  }
}
