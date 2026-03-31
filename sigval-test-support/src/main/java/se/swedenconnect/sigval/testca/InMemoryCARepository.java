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
package se.swedenconnect.sigval.testca;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.ca.repository.impl.SerializableCertificateRecord;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLMetadata;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

/**
 * Purely in-memory implementation of {@link CARepository} and {@link CRLRevocationDataProvider}
 * for use in tests. No file system I/O is performed; CRLs are stored as raw bytes in memory.
 */
public class InMemoryCARepository implements CARepository, CRLRevocationDataProvider {

  private final List<CertificateRecord> issuedCerts = Collections.synchronizedList(new ArrayList<>());
  private BigInteger crlNumber = BigInteger.ZERO;
  private byte[] currentCrlBytes;

  @Override
  public List<BigInteger> getAllCertificates() {
    return issuedCerts.stream()
        .map(CertificateRecord::getSerialNumber)
        .collect(Collectors.toList());
  }

  @Override
  public CertificateRecord getCertificate(final BigInteger serialNumber) {
    return issuedCerts.stream()
        .filter(r -> r.getSerialNumber().equals(serialNumber))
        .findFirst()
        .orElse(null);
  }

  @Override
  public void addCertificate(final X509CertificateHolder certificate) throws IOException {
    if (getCertificate(certificate.getSerialNumber()) != null) {
      throw new IOException("Certificate already exists in repository: " + certificate.getSerialNumber().toString(16));
    }
    issuedCerts.add(new SerializableCertificateRecord(
        certificate.getEncoded(),
        certificate.getSerialNumber(),
        certificate.getNotBefore(),
        certificate.getNotAfter(),
        false, null, null));
  }

  @Override
  public void revokeCertificate(final BigInteger serialNumber, final int reason, final Date revocationTime)
      throws CertificateRevocationException {
    final CertificateRecord record = getCertificate(serialNumber);
    if (record == null) {
      throw new CertificateRevocationException("No certificate with serial " + serialNumber.toString(16));
    }
    record.setRevoked(true);
    record.setReason(reason);
    record.setRevocationTime(revocationTime);
  }

  @Override
  public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  @Override
  public int getCertificateCount(final boolean notRevoked) {
    if (!notRevoked) {
      return issuedCerts.size();
    }
    return (int) issuedCerts.stream().filter(r -> !r.isRevoked()).count();
  }

  @Override
  public List<CertificateRecord> getCertificateRange(final int page, final int pageSize,
      final boolean notRevoked, final SortBy sortBy, final boolean descending) {

    List<CertificateRecord> records = issuedCerts.stream()
        .filter(r -> !notRevoked || !r.isRevoked())
        .collect(Collectors.toList());

    if (sortBy == SortBy.serialNumber) {
      records.sort(Comparator.comparing(CertificateRecord::getSerialNumber));
    }
    else if (sortBy == SortBy.issueDate) {
      records.sort(Comparator.comparing(CertificateRecord::getIssueDate));
    }

    if (descending) {
      Collections.reverse(records);
    }

    final int start = page * pageSize;
    if (start >= records.size()) {
      return new ArrayList<>();
    }
    return records.subList(start, Math.min(start + pageSize, records.size()));
  }

  @Override
  public synchronized List<BigInteger> removeExpiredCerts(final int gracePeriodSeconds) {
    final List<BigInteger> removed = new ArrayList<>();
    final Date cutoff = new Date(System.currentTimeMillis() - (1000L * gracePeriodSeconds));
    issuedCerts.removeIf(r -> {
      if (r.getExpiryDate().before(cutoff)) {
        removed.add(r.getSerialNumber());
        return true;
      }
      return false;
    });
    return removed;
  }

  // ---- CRLRevocationDataProvider ----

  @Override
  public List<RevokedCertificate> getRevokedCertificates() {
    return issuedCerts.stream()
        .filter(CertificateRecord::isRevoked)
        .map(r -> new RevokedCertificate(r.getSerialNumber(), r.getRevocationTime(), r.getReason()))
        .collect(Collectors.toList());
  }

  @Override
  public synchronized BigInteger getNextCrlNumber() {
    crlNumber = crlNumber.add(BigInteger.ONE);
    return crlNumber;
  }

  @Override
  public void publishNewCrl(final X509CRLHolder crl) throws IOException {
    this.currentCrlBytes = crl.getEncoded();
  }

  @Override
  public X509CRLHolder getCurrentCrl() {
    if (currentCrlBytes == null) {
      throw new IllegalStateException("No CRL has been published yet");
    }
    try {
      return new X509CRLHolder(currentCrlBytes);
    }
    catch (IOException e) {
      throw new IllegalStateException("Failed to parse stored CRL", e);
    }
  }

  @Override
  public CRLMetadata getCurrentCRLMetadata() {
    if (currentCrlBytes == null) {
      return CRLMetadata.builder()
          .crlNumber(BigInteger.ZERO)
          .issueTime(Instant.ofEpochMilli(0L))
          .nextUpdate(Instant.ofEpochMilli(0L))
          .revokedCertCount(0)
          .build();
    }
    try {
      final X509CRLHolder crl = new X509CRLHolder(currentCrlBytes);
      return CRLMetadata.builder()
          .crlNumber(crlNumber)
          .issueTime(crl.getThisUpdate().toInstant())
          .nextUpdate(crl.getNextUpdate().toInstant())
          .revokedCertCount(crl.getRevokedCertificates().size())
          .build();
    }
    catch (IOException e) {
      throw new IllegalStateException("Failed to parse stored CRL for metadata", e);
    }
  }
}
