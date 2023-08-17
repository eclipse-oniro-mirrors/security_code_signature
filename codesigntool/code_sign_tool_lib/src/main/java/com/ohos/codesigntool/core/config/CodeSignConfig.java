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

package com.ohos.codesigntool.core.config;

import com.ohos.codesigntool.core.api.CodeSignServer;
import com.ohos.codesigntool.core.response.DataFromSignCenterServer;
import com.ohos.codesigntool.core.sign.SignAlgorithm;
import com.ohos.codesigntool.core.utils.CertUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Signature mode super class
 *
 * @since 2023/06/05
 */
public class CodeSignConfig {
    private static final Logger LOGGER = LogManager.getLogger(CodeSignConfig.class);

    /**
     * list of x509 certificate used for sign hap
     *
     */
    private List<X509Certificate> x509CertList;

    /**
     * certificate revocation list return from server
     *
     */
    private List<X509CRL> x509CRLList;

    /**
     * list of signature Algorithm used for sign hap
     *
     */
    private List<SignAlgorithm> signAlgList;

    /**
     * map of signature param for sign hap
     *
     */
    private Map<String, String> signParamMap = new HashMap<String, String>();

    /**
     * server interface for get signature
     *
     */
    private CodeSignServer server = null;

    /**
     * fill signature parameters
     *
     * @param params input paramters for sign hap
     */
    public void setSignParamsMap(Map<String, String> params) {
        this.signParamMap = params;
    }

    /**
     * use signatureAlg to sigh the input data
     *
     * @param data unsigned data
     * @param signatureAlg name of signature Algorithm
     * @return signed data
     */
    public byte[] getSignature(byte[] data, String signatureAlg) {
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }

    /**
     * use signatureAlg with AlgorithmParameterSpec to sigh the input data
     *
     * @param data unsigned data
     * @param signatureAlg name of signature Algorithm
     * @param second paramters of signature Algorithm
     * @return signed data
     */
    public byte[] getSignature(byte[] data, String signatureAlg, AlgorithmParameterSpec second) {
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }

    /**
     * signature function.
     *
     * @param data unsigned data.
     * @param algName algorithm name.
     * @param privateKey use to sign.
     * @param second algorithm parameters.
     * @return byte array of signature.
     * @throws NoSuchProviderException get BC provider failed.
     * @throws NoSuchAlgorithmException use error algorithm.
     * @throws InvalidKeyException error key.
     * @throws InvalidAlgorithmParameterException error parameters of algorithm.
     * @throws SignatureException signing failed.
     */
    protected byte[] getSignature(byte[] data, String algName, PrivateKey privateKey, AlgorithmParameterSpec second)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, SignatureException {
        Signature signature = Signature.getInstance(algName, "BC");
        signature.initSign(privateKey);
        if (second != null) {
            signature.setParameter(second);
        }
        signature.update(data);
        return signature.sign();
    }

    /**
     * refresh crl list by object of json.
     *
     * @param data input object of DataFromSignCenterServer.
     */
    protected void refreshCrlListByResponseData(DataFromSignCenterServer data) {
        String encodeCRLData = data.getCrl();
        if (isStringDataInvalid(encodeCRLData)) {
            this.x509CRLList = null;
            LOGGER.warn("Get CRL data is null!");
        } else {
            this.x509CRLList = new ArrayList<>();
            this.x509CRLList.add(CertUtils.getX509CRLByBase64EncodedString(encodeCRLData));
        }
    }

    /**
     * refresh cert list by object of json.
     *
     * @param data input object of DataFromSignCenterServer.
     * @return true, if get certificates successfully.
     */
    protected boolean refreshCertListByResponseData(DataFromSignCenterServer data) {
        if (data.getCertchain() == null || data.getCertchain().length == 0) {
            LOGGER.error("cert chain array is empty!");
            return false;
        }

        this.x509CertList = new ArrayList<>();
        for (String cert : data.getCertchain()) {
            this.x509CertList.add(CertUtils.getX509CertByBase64EncodedString(cert));
        }
        return true;
    }

    /**
     * check whether string data is invalid.
     *
     * @param stringData string data.
     * @return true, if input is null or is empty.
     */
    protected boolean isStringDataInvalid(String stringData) {
        return (stringData == null) || StringUtils.isEmpty(stringData);
    }

    public void setSignAlgList(List<SignAlgorithm> signAlgList) {
        this.signAlgList = signAlgList;
    }

    public List<SignAlgorithm> getSignAlgList() {
        return signAlgList;
    }

    public void setX509CertList(List<X509Certificate> x509CertList) {
        this.x509CertList = x509CertList;
    }

    public List<X509Certificate> getX509CertList() {
        return x509CertList;
    }

    public void setX509CRLList(List<X509CRL> x509CRLList) {
        this.x509CRLList = x509CRLList;
    }

    public List<X509CRL> getX509CRLList() {
        return x509CRLList;
    }

    public void setSignParamMap(Map<String, String> signParamMap) {
        this.signParamMap = signParamMap;
    }

    public Map<String, String> getSignParamMap() {
        return signParamMap;
    }

    public void setServer(CodeSignServer server) {
        this.server = server;
    }

    public CodeSignServer getServer() {
        return server;
    }
}

