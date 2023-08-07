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

/**
 * Signature algorithm
 *
 * @since 2023/06/05
 */
public enum SignAlgorithm {
    RSA_PSS_WITH_SHA256(0x101, "RSA", SecureHashAlgorithm.SHA256, SignAlgorithmAndParams.SHA256_WITH_RSA_AND_MGF1),
    RSA_PSS_WITH_SHA384(0x102, "RSA", SecureHashAlgorithm.SHA384, SignAlgorithmAndParams.SHA384_WITH_RSA_AND_MGF1),
    RSA_PSS_WITH_SHA512(0x103, "RSA", SecureHashAlgorithm.SHA512, SignAlgorithmAndParams.SHA512_WITH_RSA_AND_MGF1),
    RSA_PKCS1_V1_5_WITH_SHA256(0x104, "RSA", SecureHashAlgorithm.SHA256, SignAlgorithmAndParams.SHA256_WITH_RSA),
    RSA_PKCS1_V1_5_WITH_SHA384(0x105, "RSA", SecureHashAlgorithm.SHA384, SignAlgorithmAndParams.SHA384_WITH_RSA),
    RSA_PKCS1_V1_5_WITH_SHA512(0x106, "RSA", SecureHashAlgorithm.SHA512, SignAlgorithmAndParams.SHA512_WITH_RSA),
    ECDSA_WITH_SHA256(0x201, "EC", SecureHashAlgorithm.SHA256, SignAlgorithmAndParams.SHA256_WITH_ECDSA),
    ECDSA_WITH_SHA384(0x202, "EC", SecureHashAlgorithm.SHA384, SignAlgorithmAndParams.SHA384_WITH_ECDSA),
    ECDSA_WITH_SHA512(0x203, "EC", SecureHashAlgorithm.SHA512, SignAlgorithmAndParams.SHA512_WITH_ECDSA),
    DSA_WITH_SHA256(0x301, "DSA", SecureHashAlgorithm.SHA256, SignAlgorithmAndParams.SHA256_WITH_DSA),
    DSA_WITH_SHA384(0x302, "DSA", SecureHashAlgorithm.SHA384, SignAlgorithmAndParams.SHA384_WITH_DSA),
    DSA_WITH_SHA512(0x303, "DSA", SecureHashAlgorithm.SHA512, SignAlgorithmAndParams.SHA512_WITH_DSA);

    private final int id;

    private final String keyAlgorithm;

    private final SecureHashAlgorithm secureHashAlgorithm;

    private final SignAlgorithmAndParams signAlgorithmAndParams;

    SignAlgorithm(
            int id,
            String keyAlgorithm,
            SecureHashAlgorithm secureHashAlgorithm,
            SignAlgorithmAndParams signAlgorithmAndParams) {
        this.id = id;
        this.keyAlgorithm = keyAlgorithm;
        this.secureHashAlgorithm = secureHashAlgorithm;
        this.signAlgorithmAndParams = signAlgorithmAndParams;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public int getId() {
        return id;
    }

    public SignAlgorithmAndParams getSignAlgorithmAndParams() {
        return signAlgorithmAndParams;
    }

    public SecureHashAlgorithm getSecureHashAlgorithm() {
        return secureHashAlgorithm;
    }

    /**
     * Find SignAlgorithm value by SignAlgorithm object ID.
     *
     * @param id Id of SignAlgorithm object.
     * @return SignAlgorithm value
     */
    public static SignAlgorithm findById(int id) {
        for (SignAlgorithm signAlgorithm : SignAlgorithm.values()) {
            if (id == signAlgorithm.getId()) {
                return signAlgorithm;
            }
        }
        return null;
    }
}
