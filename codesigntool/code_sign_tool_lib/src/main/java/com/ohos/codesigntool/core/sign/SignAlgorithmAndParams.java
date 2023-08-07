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

package com.ohos.codesigntool.core.sign;

import com.ohos.codesigntool.core.utils.Pair;
import com.ohos.codesigntool.core.utils.ParamConstants;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Signature algorithm and algorithmParameterSpec
 *
 * @since 2023/08/01
 */
public enum SignAlgorithmAndParams {
    SHA256_WITH_RSA_AND_MGF1(
        ParamConstants.SIG_ALGORITHM_SHA256_RSA_MGF1,
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1)),
    SHA384_WITH_RSA_AND_MGF1(
        ParamConstants.SIG_ALGORITHM_SHA384_RSA_MGF1,
        new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 384 / 8, 1)),
    SHA512_WITH_RSA_AND_MGF1(
        ParamConstants.SIG_ALGORITHM_SHA512_RSA_MGF1,
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)),
    SHA256_WITH_RSA(ParamConstants.SIG_ALGORITHM_SHA256_RSA, null),
    SHA384_WITH_RSA(ParamConstants.SIG_ALGORITHM_SHA384_RSA, null),
    SHA512_WITH_RSA(ParamConstants.SIG_ALGORITHM_SHA512_RSA, null),
    SHA256_WITH_ECDSA(ParamConstants.SIG_ALGORITHM_SHA256_ECDSA, null),
    SHA384_WITH_ECDSA(ParamConstants.SIG_ALGORITHM_SHA384_ECDSA, null),
    SHA512_WITH_ECDSA(ParamConstants.SIG_ALGORITHM_SHA512_ECDSA, null),
    SHA256_WITH_DSA(ParamConstants.SIG_ALGORITHM_SHA256_DSA, null),
    SHA384_WITH_DSA(ParamConstants.SIG_ALGORITHM_SHA384_DSA, null),
    SHA512_WITH_DSA(ParamConstants.SIG_ALGORITHM_SHA512_DSA, null);

    private final Pair<String, ? extends AlgorithmParameterSpec> pairSignAlgorithmAndParams;

    SignAlgorithmAndParams(String signAlgorithm, PSSParameterSpec params) {
        this.pairSignAlgorithmAndParams = Pair.create(signAlgorithm, params);
    }

    public Pair<String, ? extends AlgorithmParameterSpec> getPairSignAlgorithmAndParams() {
        return pairSignAlgorithmAndParams;
    }
}
