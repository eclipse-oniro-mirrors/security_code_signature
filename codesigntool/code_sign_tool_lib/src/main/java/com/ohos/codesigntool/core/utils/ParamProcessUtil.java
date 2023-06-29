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

import com.ohos.codesigntool.core.sign.SignatureAlgorithm;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Utils functions for process parameters.
 *
 * @since 2023/06/05
 */
public class ParamProcessUtil {
    private static final Logger LOGGER = LogManager.getLogger(ParamProcessUtil.class);

    /**
     * Use string array to init string set.
     *
     * @param paramFileds input string array.
     * @return string set.
     */
    public static Set<String> initParamField(String[] paramFileds) {
        return new HashSet<String>(Arrays.asList(paramFileds));
    }

    /**
     * Get SignatureAlgorithm value by algorithm name.
     *
     * @param signatureAlgorithm algorithm name.
     * @return SignatureAlgorithm value
     */
    public static SignatureAlgorithm getSignatureAlgorithm(String signatureAlgorithm) {
        if (ParamConstants.SIG_ALGORITHM_SHA256_ECDSA.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.ECDSA_WITH_SHA256;
        } else if (ParamConstants.SIG_ALGORITHM_SHA384_ECDSA.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.ECDSA_WITH_SHA384;
        } else if (ParamConstants.SIG_ALGORITHM_SHA512_ECDSA.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.ECDSA_WITH_SHA512;
        } else if (ParamConstants.SIG_ALGORITHM_SHA256_RSA_PSS.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA256;
        } else if (ParamConstants.SIG_ALGORITHM_SHA384_RSA_PSS.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA384;
        } else if (ParamConstants.SIG_ALGORITHM_SHA512_RSA_PSS.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA512;
        } else if (ParamConstants.SIG_ALGORITHM_SHA256_RSA_MGF1.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA256;
        } else if (ParamConstants.SIG_ALGORITHM_SHA384_RSA_MGF1.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA384;
        } else if (ParamConstants.SIG_ALGORITHM_SHA512_RSA_MGF1.equalsIgnoreCase(signatureAlgorithm)) {
            return SignatureAlgorithm.RSA_PSS_WITH_SHA512;
        } else {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + signatureAlgorithm);
        }
    }
}
