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

package com.ohos.test.signclient.core.api;

import com.google.gson.Gson;
import com.ohos.codesigntool.core.api.CodeSignServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * class implements CodeSignServer, use in test.
 *
 * @since 2023/06/05
 */
public class TestCodeSignServer implements CodeSignServer {
    private static final Logger LOGGER = LogManager.getLogger(TestCodeSignServer.class);
    private static final String SEPARATOR = File.separator;
    private static final String KEYSTORE =
        "src" + SEPARATOR + "test" + SEPARATOR + "resources" + SEPARATOR + "cs_cert" + SEPARATOR + "cstest.jks";
    private static final String CERTPATH =
        "src" + SEPARATOR + "test" + SEPARATOR + "resources" + SEPARATOR + "cs_cert" + SEPARATOR + "chain.pem";
    private static final String KEYSTORE_CODE = "123456";
    private static final String KEYALIAS = "oh_code_sign_test";
    private static final String KEYALIAS_CODE = "123456";

    private class ResponseJson {
        private String code;
        private String message;
        private Data data;

        ResponseJson(String code, String message, String signedData, String[] certchain, String crl) {
            this.code = code;
            this.message = message;
            this.data = new Data(signedData, certchain, crl);
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public Data getData() {
            return data;
        }

        public void setData(Data data) {
            this.data = data;
        }

        private class Data {
            private String signedData;
            private String[] certchain;
            private String crl;

            Data(String signedData, String[] certchain, String crl) {
                this.signedData = signedData;
                this.certchain = certchain;
                this.crl = crl;
            }

            public String getSignedData() {
                return signedData;
            }

            public void setSignedData(String signedData) {
                this.signedData = signedData;
            }

            public String[] getCertchain() {
                return certchain;
            }

            public void setCertchain(String[] certchain) {
                this.certchain = certchain;
            }

            public String getCrl() {
                return crl;
            }

            public void setCrl(String crl) {
                this.crl = crl;
            }
        }
    }

    @Override
    public String getSignature(byte[] data, String signatureAlg) {
        List<X509Certificate> certList = getPublicCerts(CERTPATH);
        String jsonObject = "";
        if (certList == null) {
            return jsonObject;
        }
        String[] certchain = new String[certList.size()];
        int index = 0;
        for (X509Certificate cert : certList) {
            try {
                certchain[index] =
                    "-----BEGIN CERTIFICATE-----\n"
                        + Base64.getEncoder().encodeToString(cert.getEncoded())
                        + "-----END CERTIFICATE-----\n";
                index++;
            } catch (CertificateEncodingException e) {
                LOGGER.error("get Signature failed!", e);
                return "";
            }
        }
        byte[] signData = getSignature(data, signatureAlg, null);
        String code = "success";
        String message = "sign successfully";
        String signedData = null;
        if (signData == null) {
            code = "fail";
            message = "sign failed";
        } else {
            signedData = Base64.getUrlEncoder().encodeToString(signData);
        }
        ResponseJson ret = new ResponseJson(code, message, signedData, certchain, "");
        Gson gson = new Gson();
        jsonObject = gson.toJson(ret);
        LOGGER.info(jsonObject);
        return jsonObject;
    }

    private byte[] getSignature(byte[] data, String signatureAlg, AlgorithmParameterSpec second) {
        LOGGER.info("Compute signature by {}", this.getClass().getName());
        byte[] signatureBytes = null;

        KeyStore keyStore;
        try (FileInputStream fileStream = new FileInputStream(KEYSTORE)) {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fileStream, KEYSTORE_CODE.toCharArray());
            Object obj = keyStore.getKey(KEYALIAS, KEYALIAS_CODE.toCharArray());
            if (!(obj instanceof PrivateKey)) {
                LOGGER.error("key from keystore can not be converted to PrivateKey");
                return signatureBytes;
            }
            PrivateKey privateKey = (PrivateKey) obj;
            Signature signature = Signature.getInstance(signatureAlg, "BC");
            signature.initSign(privateKey);
            if (second != null) {
                signature.setParameter(second);
            }
            signature.update(data);
            signatureBytes = signature.sign();
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | CertificateException
                | UnrecoverableKeyException
                | InvalidKeyException
                | SignatureException
                | InvalidAlgorithmParameterException
                | NoSuchProviderException
                | IOException e) {
            LOGGER.error("get Signature failed!", e);
        }
        return signatureBytes;
    }

    private List<X509Certificate> getPublicCerts(String publicCertsFile) {
        List<X509Certificate> certs = null;
        CertificateFactory cf;
        try (FileInputStream fileStream = new FileInputStream(publicCertsFile)) {
            cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = cf.generateCertificates(fileStream);
            if (certificates == null) {
                return certs;
            }

            certs = new ArrayList<X509Certificate>();
            for (Certificate cert : certificates) {
                if (cert instanceof X509Certificate) {
                    certs.add((X509Certificate) cert);
                }
            }

            if (!certs.isEmpty()) {
                Collections.reverse(certs);
            }
        } catch (CertificateException | IOException e) {
            LOGGER.error("Get public certs failed!", e);
        }
        return certs;
    }
}