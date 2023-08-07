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

import com.ohos.codesigntool.core.config.CodeSignConfig;
import com.ohos.codesigntool.core.exception.CodeSignException;

/**
 * Signed data generator interface
 *
 * @since 2023/06/05
 */
@FunctionalInterface
public interface SignedDataGenerator {
    /**
     * Creat a BcSignedDataGenerator instance
     *
     * @return BcSignedDataGenerator instance.
     */
    SignedDataGenerator BC = new BcSignedDataGenerator();

    /**
     * Generate signature data with specific content and signer configuration.
     *
     * @param content unsigned file digest content.
     * @param signConfig signer configurations.
     * @return signed data.
     * @throws CodeSignException if error.
     */
    byte[] generateSignedData(byte[] content, CodeSignConfig signConfig) throws CodeSignException;
}
