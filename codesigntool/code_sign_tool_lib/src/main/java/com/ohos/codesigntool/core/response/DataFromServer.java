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

package com.ohos.codesigntool.core.response;

/**
 * class of data from server
 *
 * @since 2023/06/05
 */
public class DataFromServer {
    /**
     * Signature data.
     */
    private String signedData;

    /**
     * Certificates chain.
     */
    private String[] certchain;

    /**
     * Certificate revocation list.
     */
    private String crl;

    public String getSignedData() {
        return signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }

    public String[] getCertchain() {
        return certchain.clone();
    }

    public void setCertchain(String[] certchain) {
        this.certchain = (certchain == null) ? new String[0] : certchain.clone();
    }

    public String getCrl() {
        return crl;
    }

    public void setCrl(String crl) {
        this.crl = crl;
    }
}