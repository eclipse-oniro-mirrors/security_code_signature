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

import com.ohos.codesigntool.core.config.CodeSignConfig;
import com.ohos.codesigntool.core.config.RemoteCodeSignConfig;

import java.security.InvalidKeyException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Remote online sign provider
 *
 * @since 2023/06/05
 */
public class RemoteCodeSignProvider extends CodeSignProvider {
    @Override
    public X509CRL getCrl() {
        return null;
    }

    @Override
    public CodeSignConfig createSignConfigs(List<X509Certificate> x509CertList, X509CRL crl)
            throws InvalidKeyException {
        CodeSignConfig signConfig = new RemoteCodeSignConfig();
        initSignConfigs(signConfig, x509CertList, crl);
        signConfig.setServer(this.server);
        return signConfig;
    }
}