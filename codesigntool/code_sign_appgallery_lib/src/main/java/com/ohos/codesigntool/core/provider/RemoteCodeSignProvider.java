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
import com.ohos.codesigntool.core.exception.InvalidParamsException;
import com.ohos.codesigntool.core.exception.MissingParamsException;
import com.ohos.codesigntool.core.sign.SignAlgorithm;
import com.ohos.codesigntool.core.utils.ParamConstants;
import com.ohos.codesigntool.core.utils.ParamProcessUtil;

import java.security.InvalidKeyException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Remote online sign provider
 *
 * @since 2023/06/05
 */
public class RemoteCodeSignProvider extends CodeSignProvider {
    @Override
    public void checkParams(String[] params) throws InvalidParamsException, MissingParamsException {
        super.checkRemoteSignParams(params);
    }

    @Override
    public X509CRL getCrl() {
        return null;
    }

    @Override
    public CodeSignConfig createSignerConfigs(List<X509Certificate> certificates, X509CRL crl)
        throws InvalidKeyException {
        CodeSignConfig signConfig = new RemoteCodeSignConfig();
        signConfig.setCertificates(certificates);
        signConfig.fillParameters(this.signParams);
        if (crl != null) {
            signConfig.setX509CRLs(Collections.singletonList(crl));
        }
        List<SignAlgorithm> signAlgorithms = new ArrayList<SignAlgorithm>();
        signAlgorithms.add(
            ParamProcessUtil.getSignAlgorithm(this.signParams.get(ParamConstants.PARAM_BASIC_SIGANTURE_ALG)));
        signConfig.setSignAlgorithms(signAlgorithms);
        signConfig.setServer(this.server);
        return signConfig;
    }
}