/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

package com.ohos.codesigntool.core.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Certificate utils class
 *
 * @since 2023/06/05
 */
public class CertUtils {
    private static final Logger LOGGER = LogManager.getLogger(CertUtils.class);

    /**
     * Get certificates chains from input file.
     *
     * @param certFilePath input file path
     * @return list of certificate chain
     */
    public static List<X509Certificate> getCertChainsFromFile(String certFilePath) {
        List<X509Certificate> x509CertList = null;
        try (FileInputStream fileStream = FileUtils.open(new File(certFilePath));) {
            x509CertList = getX509Certificates(getX509CertificateFactory(), fileStream);
        } catch (IOException e) {
            LOGGER.error("Certificate file exception: " + e.getMessage());
            return Collections.emptyList();
        }
        sortCertChain(x509CertList);
        verifyCertChain(x509CertList);
        return x509CertList;
    }

    private static List<X509Certificate> getX509Certificates(
            CertificateFactory certificateFactory, FileInputStream fileInputStream) {
        Collection<? extends Certificate> certificates = null;
        try {
            certificates = certificateFactory.generateCertificates(fileInputStream);
        } catch (CertificateException e) {
            LOGGER.error("Certificate file does not exist! " + e.getMessage());
        }
        if (certificates == null || certificates.size() == 0) {
            return Collections.emptyList();
        }
        List<X509Certificate> x509CertList = new ArrayList<>();
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
                x509CertList.add((X509Certificate) certificate);
            }
        }
        return x509CertList;
    }

    private static void verifyCertChain(List<X509Certificate> certs) {
        if (certs.size() <= 1) {
            return;
        }
        for (int i = 1; i < certs.size(); i++) {
            try {
                certs.get(i - 1).verify(certs.get(i).getPublicKey());
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
                    | NoSuchProviderException | SignatureException e) {
                LOGGER.error("verify certificate chain failed! " + e.getMessage());
            }
        }
    }

    /**
     * certificate chain reversed
     * when the last certificate subject is not equal to previous certificate issuer
     *
     * @param certificates input certificate-chain.
     */
    private static void sortCertChain(List<X509Certificate> certificates) {
        int size = certificates.size();
        if (certificates == null || size <= 1) {
            return;
        }
        X500Principal lastSubjectX500Principal = certificates.get(size - 1).getSubjectX500Principal();
        X500Principal beforeIssuerX500Principal = certificates.get(size - 2).getIssuerX500Principal();
        if (!lastSubjectX500Principal.equals(beforeIssuerX500Principal)) {
            Collections.reverse(certificates);
        }
    }

    /**
     * Get the X509Certificate object from the base64-encoded certificate string.
     *
     * @param encodeString base64-encoded certificate string.
     * @return object of X509Certificate.
     */
    public static X509Certificate getX509CertByBase64EncodedString(String encodeString) {
        String header = "-----BEGIN CERTIFICATE-----" + System.lineSeparator();
        String tail = "-----END CERTIFICATE-----" + System.lineSeparator();
        byte[] certificateDatas = null;
        if (encodeString.startsWith(header) && encodeString.endsWith(tail)) {
            certificateDatas = encodeString.getBytes(StandardCharsets.UTF_8);
        } else {
            certificateDatas = Base64.getUrlDecoder().decode(encodeString);
        }
        return getX509Certificate(certificateDatas);
    }

    /**
     * Get the x509CRL object from the base64-encoded certificate string.
     *
     * @param encodeString base64-encoded certificate string
     * @return an object of x509CRL
     */
    public static X509CRL getX509CRLByBase64EncodedString(String encodeString) {
        byte[] certificateDatas = Base64.getUrlDecoder().decode(encodeString);
        return getX509CRL(certificateDatas);
    }

    private static CertificateFactory getX509CertificateFactory() {
        CertificateFactory certificateFactory = null;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            LOGGER.error("Failed to get X509 certificateFactory ", e);
        }
        return certificateFactory;
    }

    private static X509Certificate getX509Certificate(byte[] certificateDatas) {
        CertificateFactory certificateFactory = getX509CertificateFactory();
        Certificate certificate = null;
        try {
            certificate = certificateFactory.generateCertificate(
                new ByteArrayInputStream(certificateDatas));
        } catch (CertificateException e) {
            LOGGER.error("Failed to decode base64 string as certificate", e);
        }
        if (!(certificate instanceof X509Certificate)) {
            LOGGER.error("Cannot decode input as X509 cert");
            return null;
        }
        return (X509Certificate) certificate;
    }

    private static X509CRL getX509CRL(byte[] certificateDatas) {
        CertificateFactory certificateFactory = getX509CertificateFactory();
        CRL crl = null;
        try {
            crl = certificateFactory.generateCRL(
                new ByteArrayInputStream(certificateDatas));
        } catch (CRLException e) {
            LOGGER.error("Failed to decode base64 string as crl", e);
        }
        if (!(crl instanceof X509CRL)) {
            LOGGER.error("Cannot decode input as X509 crl");
            return null;
        }
        return (X509CRL) crl;
    }
}
