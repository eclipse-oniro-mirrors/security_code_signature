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
 * class of data from signcenter server
 *
 * @since 2023/06/05
 */
public class DataFromSignCenterServer {
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

    /**
     * Set Certificates chain.
     *
     * @param certchain Giving certchain
     */
    public void setCertchain(String[] certchain) {
        if (certchain == null) {
            this.certchain = new String[0];
        } else {
            this.certchain = certchain.clone();
        }
    }

    /**
     * Get Certificates chain.
     *
     * @return Certificates chain
     */
    public String[] getCertchain() {
        return certchain.clone();
    }

    public void setCrl(String crl) {
        this.crl = crl;
    }

    public String getCrl() {
        return crl;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }

    public String getSignedData() {
        return signedData;
    }
}