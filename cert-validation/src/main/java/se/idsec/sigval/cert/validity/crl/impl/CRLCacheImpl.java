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

package se.idsec.sigval.cert.validity.crl.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.crl.CRLCacheData;
import se.idsec.sigval.cert.validity.crl.CRLCacheRecord;
import se.idsec.sigval.cert.validity.crl.CRLInfo;

/**
 * CRL cache implementation. Two main functions allows retrieval of a CRL from this cache which adds the CRL to the cache if not present,
 * and a function for re-caching all CRLs on the cache. The latter function is meant to be called periodically by a daemon process in the background
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CRLCacheImpl implements CRLCache, CRLDataLoader {

  private static final ObjectMapper jsonMapper = new ObjectMapper();
  private static final String CACHE_DATA_FILE = "crlCache.json";
  private static final String CACHE_DIR = "cache";
  private static final String TEMP_DIR = "temp";
  private static final String LDAP_CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";
  private static final String LDAP_READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";
  private static final String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  private static final int DEFAULT_CONNECT_TIMEOUT = 1000;
  private static final int DEFAULT_READ_TIMEOUT = 7000;

  private final long recacheGracePeriod;
  private CRLCacheData crlCacheData;
  private final File cacheDir;
  private final File tempDir;
  private File crlCacheFile;
  private final CRLDataLoader crlDataLoader;

  /**
   * Setter for connection timout for LDAP and HTTP
   *
   * @param connectTimeout the connection timout time in milliseconds
   */
  @Setter private int connectTimeout;
  /**
   * Setter for read timout for LDAP and HTTP
   *
   * @param readTimeout the read value timeout time in milliseconds
   */
  @Setter private int readTimeout;

  /**
   * Constructor for the CRL cache.
   *
   * @param cacheDataFolder the data folder used to store cache data
   * @param recacheGracePeriod time in milliseconds for the time after last cache instance when first re-cache will be attempted
   */
  public CRLCacheImpl(File cacheDataFolder, long recacheGracePeriod) {
    this(cacheDataFolder, recacheGracePeriod, null);
  }

  /**
   * Constructor for the CRL cache.
   *
   * @param cacheDataFolder the data folder used to store cache data
   * @param recacheGracePeriod time in milliseconds for the time after last cache instance when first re-cache will be attempted
   * @param crlDataLoader data loader for downloading CRL data or null to use default CRL data loader
   */
  public CRLCacheImpl(File cacheDataFolder, long recacheGracePeriod, CRLDataLoader crlDataLoader) {
    this.recacheGracePeriod = recacheGracePeriod;
    this.cacheDir = new File(cacheDataFolder, CACHE_DIR);
    this.tempDir = new File(cacheDataFolder, TEMP_DIR);
    this.crlCacheFile = new File(cacheDataFolder, CACHE_DATA_FILE);
    this.connectTimeout = DEFAULT_CONNECT_TIMEOUT;
    this.readTimeout = DEFAULT_READ_TIMEOUT;
    if (!cacheDir.exists()) {
      cacheDir.mkdirs();
    }
    if (!tempDir.exists()) {
      tempDir.mkdirs();
    }
    this.crlDataLoader = (crlDataLoader == null) ? this : crlDataLoader;
    recache();
  }

  /**
   * Returns the current list of cached CRL records
   * @return list of cached CRLs
   */
  public List<CRLCacheRecord> getCrlCacheRecords() {
    return crlCacheData.getCrlCacheRecordList();
  }

  /**
   * This function is a more practical use of the cache rather than asking for a particular cached URL. This function is however
   * limited to the following specific usage policy:
   * <ul>
   *   <li>Only distribution points with absent reason settings are accepted (Not limited to a subset of reasons)</li>
   *   <li>Only distribution points with absent crlIssuer are accepted (CRL must be issued by cert issuer)</li>
   *   <li>Both LDAP(S) and HTTP(S) sources are accepted</li>
   *   <li>If both LDAP and HTTP sources are present, HTTP is attempted first. LDAP will only be attempted if HTTP fails</li>
   *   <li>If several sources are present, only the first successful source will be cached</li>
   * </ul>
   *
   * @param crlDistributionPointExt CRL distribution point extension
   * @return CRL
   * @throws IOException on error to obtain the CRL from this extension
   */
  @Override public CRLInfo getCRL(CRLDistPoint crlDistributionPointExt) throws IOException{
    List<String> approvedUriList = new ArrayList<>();
    boolean crlIssuerPresent = false;
    boolean reasonsPresent = false;
    DistributionPoint[] distributionPoints = crlDistributionPointExt.getDistributionPoints();
    for (DistributionPoint dp : distributionPoints) {
      GeneralNames crlIssuer = dp.getCRLIssuer();
      ReasonFlags reasons = dp.getReasons();
      GeneralNames dpGeneralNames = GeneralNames.getInstance(dp.getDistributionPoint().getName());
      List<String> uriNameList = Arrays.stream(dpGeneralNames.getNames())
        .filter(generalName -> generalName.getTagNo() == GeneralName.uniformResourceIdentifier)
        .map(generalName -> ((DERIA5String) generalName.getName()).getString())
        .collect(Collectors.toList());

      for (String uri: uriNameList){
        if (uri !=null && crlIssuer == null && reasons == null) {
          // This distribution point meets the basic acceptance criteria
          approvedUriList.add(uri);
        } else {
          // This distribution point does not meet basic acceptance criteria. Store reason for proper error logging
          crlIssuerPresent = crlIssuer != null || crlIssuerPresent;
          reasonsPresent = reasons != null || reasonsPresent;
        }
      }

    }
    if (approvedUriList.isEmpty()){
      // We didnt find any acceptable distribution points. Throw exception
      if (crlIssuerPresent){
        log.debug("No acceptable CRL distribution point found. Declaration of crlIssuer is not allowed");
        throw new IOException("No acceptable CRL distribution point found. Declaration of crlIssuer is not allowed");
      }
      if (reasonsPresent){

        log.debug("No acceptable CRL distribution point found. Declaration of reason is not allowed");
        throw new IOException("No acceptable CRL distribution point found. Declaration of reason is not allowed");
      }
    }

    log.debug("Found valid CRLDP URL:s " + String.join(", ", approvedUriList));

    // We have at least one acceptable URI
    Optional<String> httpUrlOptional = approvedUriList.stream()
      .filter(s -> s != null && s.toLowerCase().startsWith("http"))
      .findFirst();
    Optional<String> ldapUrlOptional = approvedUriList.stream()
      .filter(s -> s != null && s.toLowerCase().startsWith("ldap"))
      .findFirst();


    if (httpUrlOptional.isPresent()){
      try {
        return getCRL(httpUrlOptional.get());
      } catch (Exception ex) {
        log.debug("Attempt to cache CRL from http URL failed: " + ex.getMessage() + " - attempting other URLs if present");
      }
    }

    if (ldapUrlOptional.isPresent()){
      try {
        return getCRL(ldapUrlOptional.get());
      } catch (Exception ex) {
        log.debug("Attempt to cache CRL from ldap URL failed: " + ex.getMessage());
      }
    }
    throw new IOException("No valid CRL could be obtained from the provided CRL distribution point");
  }

  /**
   * Retrieves a CRL from the CRL cache. If the CRL is not in the cache or if the cached CRL is expired,
   * then an attempt to download and cache the CRL is made.
   *
   * @param url the location of the CRL
   * @return cached or downloaded CRL
   * @throws IOException if it is not possible to obtain a CRL from this location
   */
  @Override public CRLInfo getCRL(String url) throws IOException {
    try {
      new URI(url);
    }
    catch (Exception ex) {
      log.warn("Malformed url in requested CRL: " + url);
      throw new IOException("Malformed url in requested CRL: " + url);
    }

    Optional<CRLCacheRecord> cacheRecordOptional = crlCacheData.getCrlCacheRecordList().stream()
      .filter(crlCacheRecord -> url.equalsIgnoreCase(crlCacheRecord.getUrl()))
      .findFirst();

    if (cacheRecordOptional.isPresent()) {
      // This CRL is cached. check if it is still valid
      X509CRL cachedCrl = getCachedCrl(cacheRecordOptional.get().getFileName());
      Date nextUpdate = cachedCrl.getNextUpdate();
      if (nextUpdate.after(new Date())) {
        log.debug("Returning cached CRL for location: " + url);
        return CRLInfo.builder().crl(cachedCrl).location(cacheRecordOptional.get().getUrl()).build();
      }
      else {
        log.debug("Cached CRL expired for location " + url);
      }
    }
    else {
      log.debug("No cached CRL present for location " + url);
    }

    // Reaching this point means that the CRL is not cached or the cached CRL has expired.
    log.debug("Attempting to cache CRL from " + url);
    try {
      CRLCacheRecord crlCacheRecord = CRLCacheRecord.builder()
        .url(url)
        .fileName(getFileName(url))
        .build();

      // Cache CRL
      cacheCrlRecord(crlCacheRecord);
      // Add cache record data
      crlCacheData.getCrlCacheRecordList().add(crlCacheRecord);
      // Save cache data file
      FileUtils.writeByteArrayToFile(crlCacheFile, jsonMapper.writeValueAsBytes(crlCacheData));
      // Return cached CRL
      return CRLInfo.builder().crl(getCachedCrl(crlCacheRecord.getFileName())).location(crlCacheRecord.getUrl()).build();
    }
    catch (Exception ex) {
      log.warn("Unable to cache CRL from " + url + " " + ex.getMessage());
      throw new IOException(ex.getMessage());
    }
  }

  /**
   * Performs a re-cache of all cached CRL records. This method should be called by a daemon process periodically
   */
  @Override public void recache() {
    log.info("Re-caching CRL data...");
    List<String> badUrlList = new ArrayList<>();
    try {
      //Reload configuration
      reloadCrlCacheData();
      crlCacheData.getCrlCacheRecordList().stream().forEach(crlCacheRecord -> {
        try {
          //Attempt to reload this cache
          log.debug("Re-caching CRL from {}", crlCacheRecord.getUrl());
          cacheCrlRecord(crlCacheRecord);
        }
        catch (Exception ex) {
          log.warn("Unable to cache CRL from: " + crlCacheRecord.getUrl() + ". Removing it from cache. " + ex.getMessage());
          badUrlList.add(crlCacheRecord.getUrl());
        }
      });

      if (!badUrlList.isEmpty()) {
        // We found bad URL:s that could not be cached. We remove them from the cache for now.
        List<CRLCacheRecord> filteredCacheRecords = crlCacheData.getCrlCacheRecordList().stream()
          .filter(crlCacheRecord -> !badUrlList.contains(crlCacheRecord.getUrl()))
          .collect(Collectors.toList());
        // Remove cached CRL
        crlCacheData.getCrlCacheRecordList().stream()
          .filter(crlCacheRecord -> badUrlList.contains(crlCacheRecord.getUrl()))
          .forEach(crlCacheRecord -> {
            File cacheFile = new File(cacheDir, crlCacheRecord.getFileName());
            cacheFile.delete();
          });
        // Set the consolidated list
        crlCacheData.setCrlCacheRecordList(filteredCacheRecords);
      }
      // Save cache data file, storing any changes made to it.
      FileUtils.writeByteArrayToFile(crlCacheFile, jsonMapper.writeValueAsBytes(crlCacheData));
    }
    catch (Exception e) {
      log.error("Unable to re-cache CRL data", e);
      return;
    }
  }

  /**
   * Download a CRL based on the CRL cache record
   * @param crlCacheRecord CRL cache record
   * @throws Exception errors preventing the CRL from being downloaded
   */
  private void cacheCrlRecord(CRLCacheRecord crlCacheRecord) throws Exception {
    String urlStr = crlCacheRecord.getUrl();
    if (System.currentTimeMillis() < crlCacheRecord.getLastCache() + recacheGracePeriod) {
      log.debug("Crl " + urlStr + " is recently cached. Skipping this re-cache");
      return;
    }
    log.debug("Re-caching CRL from: " + urlStr);
    File tempFile = new File(tempDir, crlCacheRecord.getFileName());
    File cacheFile = new File(cacheDir, crlCacheRecord.getFileName());

    byte[] downloadedCrlBytes = crlDataLoader.downloadCrl(urlStr, connectTimeout, readTimeout);
    FileUtils.writeByteArrayToFile(tempFile, downloadedCrlBytes);

    // If data was downloaded but deletion is not done due to exception condition. Then at least remove temp file on exit.
    tempFile.deleteOnExit();
    X509CRL crl = getCachedCrl(tempFile);
    Date nextUpdate = crl.getNextUpdate();
    if (nextUpdate.before(new Date())) {
      tempFile.delete();
      throw new IOException("Downloaded CRL expired " + nextUpdate.toString());
    }
    crlCacheRecord.setNextUpdate(nextUpdate.getTime());
    crlCacheRecord.setLastCache(System.currentTimeMillis());
    FileUtils.copyFile(tempFile, cacheFile);
    tempFile.delete();
  }

  private X509CRL getCachedCrl(String fileName) throws IOException {
    File cacheFile = new File(cacheDir, fileName);
    try {
      return getCachedCrl(cacheFile);
    }
    catch (Exception e) {
      throw new IOException(e.getMessage());
    }
  }

  private X509CRL getCachedCrl(File crlFile) throws Exception {
    InputStream inStream = null;
    try {
      inStream = new FileInputStream(crlFile);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509CRL) cf.generateCRL(inStream);
    }
    finally {
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  private void reloadCrlCacheData() throws Exception {
    if (!crlCacheFile.canRead()) {
      crlCacheData = CRLCacheData.builder().crlCacheRecordList(new ArrayList<>()).build();
      FileUtils.writeByteArrayToFile(crlCacheFile, jsonMapper.writeValueAsBytes(crlCacheData));
      return;
    }
    crlCacheData = jsonMapper.readValue(crlCacheFile, CRLCacheData.class);
  }

  private String getFileName(String url) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-1");
    return new BigInteger(1, digest.digest(url.getBytes(StandardCharsets.UTF_8))).toString(32) + ".crl";

  }

  /** {@inheritDoc} */
  @Override
  public byte[] downloadCrl(String urlStr, int connectTimeout, int readTimeout) throws IOException {
    if (urlStr.toLowerCase().startsWith("http")) {
      URL url = new URL(urlStr);
      URLConnection connection = url.openConnection();
      connection.setConnectTimeout(connectTimeout);
      connection.setReadTimeout(readTimeout);
      connection.setDefaultUseCaches(true);
      return IOUtils.toByteArray(connection);
    }
    if (urlStr.toLowerCase().startsWith("ldap")) {
      try {
        return downloadCRLFromLDAP(urlStr);
      }
      catch (NamingException e) {
        throw new IOException("Failed to download LDAP CRL", e);
      }
    }
    throw new IOException("Illegal URL for CRL downloads");
  }

  /**
   * Downloads a CRL from given LDAP url, e.g.
   * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
   */
  private byte[] downloadCRLFromLDAP(String ldapURL)
    throws NamingException, IOException {
    Hashtable<String, String> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CONTEXT_FACTORY);
    env.put(LDAP_CONNECT_TIMEOUT, String.valueOf(connectTimeout));
    env.put(LDAP_READ_TIMEOUT, String.valueOf(readTimeout));
    env.put(Context.PROVIDER_URL, ldapURL);

    DirContext ctx = new InitialDirContext(env);
    Attributes avals = ctx.getAttributes("");
    Attribute aval = avals.get("certificateRevocationList;binary");
    byte[] val = (byte[]) aval.get();
    if ((val == null) || (val.length == 0)) {
      throw new IOException(
        "Can not download CRL from: " + ldapURL);
    }
    else {
      return val;
    }
  }

}
