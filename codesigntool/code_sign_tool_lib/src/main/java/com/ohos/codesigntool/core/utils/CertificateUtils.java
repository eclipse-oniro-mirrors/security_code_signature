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

import com.ohos.codesigntool.core.exception.VerifyCertificateChainException;
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
 * Class include some utils about certificate.
 *
 * @since 2023/06/05
 */
public class CertificateUtils {
    private static final Logger LOGGER = LogManager.getLogger(CertificateUtils.class);

    private static void verifyCertChain(List<X509Certificate> certs) throws VerifyCertificateChainException {
        if (certs.size() <= 1) {
            return;
        }
        for (int i = 1; i < certs.size(); i++) {
            try {
                certs.get(i - 1).verify(certs.get(i).getPublicKey());
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
                    | NoSuchProviderException | SignatureException e) {
                throw new VerifyCertificateChainException("verify certificate chain failed! " + e.getMessage());
            }
        }
    }

    /**
     * Get certificates chains from input file.
     *
     * @param certsFile input file
     * @return list of certificate chain
     * @throws IOException                     file is not exist
     * @throws CertificateException            data in file is not certificate
     * @throws VerifyCertificateChainException cerificates in file are not certificate chain
     */
    public static List<X509Certificate> getCertListFromFile(String certsFile) throws IOException, CertificateException,
            VerifyCertificateChainException {
        try (FileInputStream fileInputStream = FileUtils.openInputStream(new File(certsFile));) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = cf.generateCertificates(fileInputStream);
            if (certificates == null || certificates.size() == 0) {
                return Collections.emptyList();
            }
            final List<X509Certificate> certs = new ArrayList<>();
            certificates.forEach(certificate -> {
                if (certificate instanceof X509Certificate) {
                    certs.add((X509Certificate) certificate);
                }
            });
            sortCertificateChain(certs);
            verifyCertChain(certs);
            return certs;
        }
    }

    /**
     * If the last certificate subject is not equal to previous certificate issuer,
     * the certificate-chain need be reversed.
     *
     * @param certificates input certificate-chain.
     */
    private static void sortCertificateChain(List<X509Certificate> certificates) {
        if (certificates != null && certificates.size() > 1) {
            int size = certificates.size();
            X500Principal lastSubjectX500Principal = certificates.get(size - 1).getSubjectX500Principal();
            X500Principal beforeIssuerX500Principal = certificates.get(size - 2).getIssuerX500Principal();
            if (!lastSubjectX500Principal.equals(beforeIssuerX500Principal)) {
                Collections.reverse(certificates);
            }
        }
    }

    /**
     * Input a string of certificate with base64 encoded, and output an object of X509Certificate.
     *
     * @param encodeString string of certificate with base64 encoded.
     * @return object of X509Certificate.
     */
    public static X509Certificate decodeBase64ToX509Certifate(String encodeString) {
        String header = "-----BEGIN CERTIFICATE-----\n";
        String tail = "-----END CERTIFICATE-----\n";
        byte[] certificateDatas = null;
        X509Certificate x509Certificate = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            if (encodeString.startsWith(header) && encodeString.endsWith(tail)) {
                certificateDatas = encodeString.getBytes(StandardCharsets.UTF_8);
            } else {
                certificateDatas = Base64.getUrlDecoder().decode(encodeString);
            }
            Certificate obj = cf.generateCertificate(new ByteArrayInputStream(certificateDatas));
            if (!(obj instanceof X509Certificate)) {
                LOGGER.error("generateCertificate is not x509");
                return x509Certificate;
            }
            x509Certificate = (X509Certificate) obj;
        } catch (CertificateException e) {
            LOGGER.error("Decode Base64 certificate failed!", e);
        }
        return x509Certificate;
    }

    /**
     * Get an object of x509CRL from a string of certificate with base64 encoded.
     *
     * @param encodeString string of certificate with base64 encoded
     * @return an object of x509CRL
     */
    public static X509CRL decodeBase64ToX509CRL(String encodeString) {
        byte[] certificateDatas = Base64.getUrlDecoder().decode(encodeString);

        X509CRL x509CRL = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CRL obj = cf.generateCRL(new ByteArrayInputStream(certificateDatas));
            if (!(obj instanceof X509CRL)) {
                LOGGER.error("generateCRL is not x509");
                return x509CRL;
            }
            x509CRL = (X509CRL) obj;
        } catch (CRLException | CertificateException e) {
            LOGGER.error("Decode Base64 crl failed!");
        }
        return x509CRL;
    }
}
