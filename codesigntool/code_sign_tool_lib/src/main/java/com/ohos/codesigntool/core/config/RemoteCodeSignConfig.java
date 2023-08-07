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

package com.ohos.codesigntool.core.config;

import com.google.gson.Gson;
import com.ohos.codesigntool.core.response.DataFromAppGallaryServer;
import com.ohos.codesigntool.core.response.DataFromSignCenterServer;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

/**
 * Signature code by remote server online
 *
 * @since 2023/06/05
 */
public class RemoteCodeSignConfig extends CodeSignConfig {
    private static final Logger LOGGER = LogManager.getLogger(RemoteCodeSignConfig.class);
    @Override
    public byte[] getSignature(byte[] data, String signatureAlg, AlgorithmParameterSpec second) {
        LOGGER.info("Compute signature by remote mode!");
        if (this.getServer() == null) {
            LOGGER.error("server is null");
            return null;
        }
        String responseData = this.getServer().getSignature(data, signatureAlg);
        byte[] signatureBytes = getSignatureFromServer(responseData);
        if (signatureBytes != null && signatureBytes.length > 0) {
            LOGGER.info("Get signature success!");
        } else {
            LOGGER.error("Get signature failed!");
            return null;
        }
        return signatureBytes;
    }

    /**
     * parse data replied from server and get signature
     *
     * @param responseData data replied from server
     * @return binary data of signature
     */
    public byte[] getSignatureFromServer(String responseData) {
        if (isStringDataInvalid(responseData)) {
            LOGGER.error("Get invalid response from signature server!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
        DataFromAppGallaryServer dataFromAppGallaryServer =
            new Gson().fromJson(responseData, DataFromAppGallaryServer.class);
        if (dataFromAppGallaryServer == null || !checkSignaturesIsSuc(dataFromAppGallaryServer)) {
            LOGGER.error("responseJson is illegals!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        DataFromSignCenterServer signCenterData =
            dataFromAppGallaryServer.getDataFromSignCenterServer();
        if (signCenterData == null) {
            LOGGER.error("Get response data error!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        if (!getCertificatesFromResponseData(signCenterData)) {
            LOGGER.error("Get certificate list data error!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        getCrlFromResponseData(signCenterData);

        String encodeSignedData = signCenterData.getSignedData();
        if (isStringDataInvalid(encodeSignedData)) {
            LOGGER.error("Get signedData data error!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
        return Base64.getUrlDecoder().decode(encodeSignedData);
    }

    private boolean checkSignaturesIsSuc(DataFromAppGallaryServer dataFromAppGallaryServer) {
        if (!"success".equals(dataFromAppGallaryServer.getCodeSignature())) {
            if (dataFromAppGallaryServer.getMessage() != null) {
                LOGGER.error("Get signedData failed: {}", dataFromAppGallaryServer.getMessage());
            }
            return false;
        }
        return true;
    }

}
