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

/**
 * define const parameters.
 *
 * @since 2023/06/05
 */
public class ParamConstants {

    /**
     * Signature Algorithm name of SHA256withECDSA
     */
    public static final String SIG_ALGORITHM_SHA256_ECDSA = "SHA256withECDSA";

    /**
     * Signature Algorithm name of SHA384withECDSA
     */
    public static final String SIG_ALGORITHM_SHA384_ECDSA = "SHA384withECDSA";

    /**
     * Signature Algorithm name of SHA512withECDSA
     */
    public static final String SIG_ALGORITHM_SHA512_ECDSA = "SHA512withECDSA";

    /**
     * Signature Algorithm name of SHA256withRSA
     */
    public static final String SIG_ALGORITHM_SHA256_RSA = "SHA256withRSA";

    /**
     * Signature Algorithm name of SHA384withRSA
     */
    public static final String SIG_ALGORITHM_SHA384_RSA = "SHA384withRSA";

    /**
     * Signature Algorithm name of SHA512withRSA
     */
    public static final String SIG_ALGORITHM_SHA512_RSA = "SHA512withRSA";

    /**
     * Signature Algorithm name of SHA256withRSA/PSS
     */
    public static final String SIG_ALGORITHM_SHA256_RSA_PSS = "SHA256withRSA/PSS";

    /**
     * Signature Algorithm name of SHA384withRSA/PSS
     */
    public static final String SIG_ALGORITHM_SHA384_RSA_PSS = "SHA384withRSA/PSS";

    /**
     * Signature Algorithm name of SHA512withRSA/PSS
     */
    public static final String SIG_ALGORITHM_SHA512_RSA_PSS = "SHA512withRSA/PSS";

    /**
     * Signature Algorithm name of SHA256withRSAANDMGF1
     */
    public static final String SIG_ALGORITHM_SHA256_RSA_MGF1 = "SHA256withRSAANDMGF1";

    /**
     * Signature Algorithm name of SHA384withRSAANDMGF1
     */
    public static final String SIG_ALGORITHM_SHA384_RSA_MGF1 = "SHA384withRSAANDMGF1";

    /**
     * Signature Algorithm name of SHA512withRSAANDMGF1
     */
    public static final String SIG_ALGORITHM_SHA512_RSA_MGF1 = "SHA512withRSAANDMGF1";

    /**
     * Signature Algorithm name of SHA256withDSA
     */
    public static final String SIG_ALGORITHM_SHA256_DSA = "SHA256withDSA";

    /**
     * Signature Algorithm name of SHA384withDSA
     */
    public static final String SIG_ALGORITHM_SHA384_DSA = "SHA384withDSA";

    /**
     * Signature Algorithm name of SHA512withDSA
     */
    public static final String SIG_ALGORITHM_SHA512_DSA = "SHA512withDSA";

    /**
     * Certificate revoke list.
     */
    public static final String PARAM_BASIC_CRL = "crl";

    /**
     * Private key used in signature.
     */
    public static final String PARAM_BASIC_PRIVATE_KEY = "privatekey";

    /**
     * File used to sign.
     */
    public static final String PARAM_BASIC_INPUT_FILE = "inputFile";

    /**
     * Signed file.
     */
    public static final String PARAM_BASIC_OUTPUT_PATH = "outputPath";

    /**
     * Algorithm name of signatures.
     */
    public static final String PARAM_BASIC_SIGN_ALG = "signAlg";

    /**
     * Flag indicates whether profile is signed.
     */
    public static final String PARAM_OUTPUT_MEKLE_TREE = "outTree";

    /**
     * The certificate-file path.
     */
    public static final String PARAM_LOCAL_PUBLIC_CERT = "certpath";
}
