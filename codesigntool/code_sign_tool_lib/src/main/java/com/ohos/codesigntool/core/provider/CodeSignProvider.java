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

package com.ohos.codesigntool.core.provider;

import com.ohos.codesigntool.core.api.CodeSignServer;
import com.ohos.codesigntool.core.config.CodeSignConfig;
import com.ohos.codesigntool.core.exception.FsVerityDigestException;
import com.ohos.codesigntool.core.exception.InvalidParamsException;
import com.ohos.codesigntool.core.exception.MissingParamsException;
import com.ohos.codesigntool.core.exception.CodeSignException;
import com.ohos.codesigntool.core.sign.SignCode;
import com.ohos.codesigntool.core.sign.SignAlgorithm;
import com.ohos.codesigntool.core.utils.CertUtils;
import com.ohos.codesigntool.core.utils.FileUtils;
import com.ohos.codesigntool.core.utils.ParamConstants;
import com.ohos.codesigntool.core.utils.ParamProcessUtil;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * provider for code sign
 *
 * @since 2023/06/05
 */
public abstract class CodeSignProvider {
    private static final Logger LOGGER = LogManager.getLogger(CodeSignProvider.class);
    private static final List<String> VALID_SIGN_ALG_NAME = new ArrayList<String>();
    private static final String SIGNATURE_FILE_SUFFIX = ".sig";

    static {
        VALID_SIGN_ALG_NAME.add(ParamConstants.SIG_ALGORITHM_SHA256_ECDSA);
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * parameters input by signer
     */
    protected Map<String, String> inputParams = new HashMap<String, String>();

    /**
     * parameters only use in signing
     */
    protected Map<String, String> signParams = new HashMap<String, String>();

    /**
     * interface of sign server
     */
    protected CodeSignServer server = null;

    /**
     * set interface of sign server
     *
     * @param server interface of sign server
     */
    public void setCodeSignServer(CodeSignServer server) {
        this.server = server;
    }

    /**
     * Get certificate chain used to sign.
     *
     * @return list of x509 certificates.
     */
    private List<X509Certificate> getPublicCerts() {
        String publicCertPath = signParams.get(ParamConstants.PARAM_LOCAL_PUBLIC_CERT);
        if (StringUtils.isEmpty(publicCertPath)) {
            return Collections.emptyList();
        }
        return CertUtils.getCertChainsFromFile(publicCertPath);
    }

    /**
     * get certificate revocation list used to sign
     *
     * @return certificate revocation list
     */
    public abstract X509CRL getCrl();


    /**
     * Create SignerConfig by certificate chain and certificate revocation list.
     *
     * @param certificates certificate chain
     * @param crl certificate revocation list
     * @return Object of SignerConfig
     * @throws InvalidKeyException on error when the key is invalid.
     */
    public CodeSignConfig createSignerConfigs(List<X509Certificate> certificates, X509CRL crl)
            throws InvalidKeyException {
        CodeSignConfig signConfig = new CodeSignConfig();
        signConfig.fillParameters(this.signParams);
        signConfig.setCertificates(certificates);

        List<SignAlgorithm> signatureAlgorithms = new ArrayList<>();
        signatureAlgorithms.add(
            ParamProcessUtil.getSignAlgorithm(this.signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG)));
        signConfig.setSignAlgorithms(signatureAlgorithms);

        if (crl != null) {
            signConfig.setX509CRLs(Collections.singletonList(crl));
        }
        return signConfig;
    }

    /**
     * sign code
     *
     * @param params parameters used to sign code
     * @return true, if sign successfully
     */
    public boolean sign(String[] params) {
        File output = null;
        try {
            // 1. check the parameters
            checkParams(params);
            // 2. get x509 certificate
            List<X509Certificate> publicCerts = getPublicCerts();
            // 3. check input hap validation
            File input = new File(signParams.get(ParamConstants.PARAM_BASIC_INPUT_FILE));
            FileUtils.isValid(input);
            // 4. generate output file path
            String outputPath = signParams.get(ParamConstants.PARAM_BASIC_OUTPUT_PATH);
            if (!outputPath.endsWith(File.separator)) {
                outputPath += File.separator;
            }
            String outputFile = outputPath + input.getName() + SIGNATURE_FILE_SUFFIX;
            output = new File(outputFile);
            // 5. check whether store tree
            String outTreeSwitch = signParams.get(ParamConstants.PARAM_OUTPUT_MEKLE_TREE);
            boolean storeTree = (outTreeSwitch != null) && (outTreeSwitch.equals("true"));
            // 6. sign code
            CodeSignConfig signConfig = createSignerConfigs(publicCerts, getCrl());
            SignCode signCode = new SignCode(signConfig);
            signCode.signCode(input, output, storeTree);
        } catch (CodeSignException | IOException | InvalidKeyException |
            MissingParamsException | InvalidParamsException | FsVerityDigestException e) {
            printErrorLog(e);
            return false;
        }
        return true;
    }

    private void printErrorLog(Exception exception) {
        if (exception != null) {
            LOGGER.error("code-sign-tool: error: {}", exception.getMessage(), exception);
        }
    }

    /**
     * check output signature path
     *
     * @throws MissingParamsException Exception occurs when the outputted file path is not entered.
     */
    protected void checkOutputPath() throws MissingParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_BASIC_OUTPUT_PATH)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_BASIC_OUTPUT_PATH);
        }
    }

    /**
     * Check input parameters is valid. And put valid parameters input signParams.
     *
     * @param params parameters input by user.
     * @throws MissingParamsException Exception occurs when the required parameters are not entered.
     * @throws InvalidParamsException Exception occurs when the inputted parameters are invalid.
     */
    public void checkParams(String[] params) throws MissingParamsException, InvalidParamsException {
        checkRemoteSignParams(params);
    }

    /**
     * Check input parameters used to remotesign file is valid. And put valid parameters input signParams.
     *
     * @param params parameters input by user.
     * @throws MissingParamsException Exception occurs when the required parameters are not entered.
     * @throws InvalidParamsException Exception occurs when the inputted parameters are invalid.
     */
    protected void checkRemoteSignParams(String[] params) throws InvalidParamsException, MissingParamsException {
        for (int i = 0; i < params.length; i += 2) {
            if (!params[i].startsWith("-")) {
                continue;
            }
            String paramName = params[i].substring(1);
            String paramValue = params[i + 1];
            inputParams.put(paramName, paramValue);
        }

        String[] paramFields = {
                ParamConstants.PARAM_BASIC_SIGANTURE_ALG,
                ParamConstants.PARAM_BASIC_INPUT_FILE,
                ParamConstants.PARAM_BASIC_OUTPUT_PATH,
                ParamConstants.PARAM_OUTPUT_MEKLE_TREE
        };
        Set<String> paramSet = ParamProcessUtil.initParamField(paramFields);

        for (Map.Entry<String, String> entry : inputParams.entrySet()) {
            if (paramSet.contains(entry.getKey())) {
                signParams.put(entry.getKey(), inputParams.get(entry.getKey()));
            }
        }

        checkSignatureAlg();
        checkInputFile();
        checkOutputPath();
    }

    /**
     * check input hap file
     *
     * @throws MissingParamsException Exception occurs when unsigned file is not entered.
     */
    protected void checkInputFile() throws MissingParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_BASIC_INPUT_FILE)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_BASIC_INPUT_FILE);
        }
    }

    /**
     * check signature algorithm
     *
     * @throws MissingParamsException Exception occurs when the name of sign algorithm is not entered.
     * @throws InvalidParamsException Exception occurs when the inputted sign algorithm is invalid.
     */
    private void checkSignatureAlg() throws MissingParamsException, InvalidParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_BASIC_SIGANTURE_ALG)) {
            LOGGER.error("Missing parameter : " + ParamConstants.PARAM_BASIC_SIGANTURE_ALG);
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_BASIC_SIGANTURE_ALG);
        }

        String signAlg = signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG).trim();
        for (String validAlg : VALID_SIGN_ALG_NAME) {
            if (validAlg.equalsIgnoreCase(signAlg)) {
                return;
            }
        }
        LOGGER.error("Unsupported signature algorithm :" + signAlg);
        throw new InvalidParamsException("Invalid parameter: Sign Alg");
    }
}
