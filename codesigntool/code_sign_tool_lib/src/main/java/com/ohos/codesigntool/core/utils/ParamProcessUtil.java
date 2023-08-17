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

import com.ohos.codesigntool.core.sign.SignAlgorithm;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.TreeMap;

/**
 * Utils functions for process parameters.
 *
 * @since 2023/06/05
 */
public class ParamProcessUtil {
    private static final Logger LOGGER = LogManager.getLogger(ParamProcessUtil.class);
    private static Map<String, SignAlgorithm> mapSignAlg =
        new TreeMap<String, SignAlgorithm>(String.CASE_INSENSITIVE_ORDER);

    static {
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA256_ECDSA, SignAlgorithm.ECDSA_WITH_SHA256);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA384_ECDSA, SignAlgorithm.ECDSA_WITH_SHA384);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA512_ECDSA, SignAlgorithm.ECDSA_WITH_SHA512);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA256_RSA_PSS, SignAlgorithm.RSA_PSS_WITH_SHA256);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA384_RSA_PSS, SignAlgorithm.RSA_PSS_WITH_SHA384);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA512_RSA_PSS, SignAlgorithm.RSA_PSS_WITH_SHA512);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA256_RSA_MGF1, SignAlgorithm.RSA_PSS_WITH_SHA256);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA384_RSA_MGF1, SignAlgorithm.RSA_PSS_WITH_SHA384);
        mapSignAlg.put(ParamConstants.SIG_ALGORITHM_SHA512_RSA_MGF1, SignAlgorithm.RSA_PSS_WITH_SHA512);
    }

    /**
     * Get SignAlgorithm value by algorithm name.
     *
     * @param signAlgorithm algorithm name.
     * @return SignAlgorithm value
     */
    public static SignAlgorithm getSignAlgorithm(String signAlgorithm) {
        if (!mapSignAlg.containsKey(signAlgorithm)) {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + signAlgorithm);
        }
        return mapSignAlg.get(signAlgorithm);
    }
}
