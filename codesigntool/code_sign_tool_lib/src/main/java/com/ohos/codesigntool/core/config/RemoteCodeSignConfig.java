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
        byte[] signBytes = getSignFromServer(responseData);
        if (signBytes != null && signBytes.length > 0) {
            LOGGER.info("Get signature data success!");
        } else {
            LOGGER.error("Get signature data failed!");
            return null;
        }
        return signBytes;
    }

    /**
     * parse response data from server and return the decrypted signature data.
     *
     * @param responseData response data from server
     * @return binary data of signature
     */
    public byte[] getSignFromServer(String responseData) {
        if (isStringDataInvalid(responseData)) {
            LOGGER.error("Get invalid response from signature server!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
        DataFromAppGallaryServer dataFromAppGallaryServer =
            new Gson().fromJson(responseData, DataFromAppGallaryServer.class);
        if (dataFromAppGallaryServer == null || !isSignSuccess(dataFromAppGallaryServer)) {
            LOGGER.error("ResponseJson is illegals!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        DataFromSignCenterServer signCenterData =
            dataFromAppGallaryServer.getDataFromSignCenterServer();
        if (signCenterData == null) {
            LOGGER.error("Get response data from sign center server error!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        if (!refreshCertListByResponseData(signCenterData)) {
            LOGGER.error("Refresh certificate list data failed!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }

        refreshCrlListByResponseData(signCenterData);

        String encodeSignedData = signCenterData.getSignedData();
        if (isStringDataInvalid(encodeSignedData)) {
            LOGGER.error("Get signedData data error!");
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
        return Base64.getUrlDecoder().decode(encodeSignedData);
    }

    private boolean isSignSuccess(DataFromAppGallaryServer dataFromAppGallaryServer) {
        if (!"success".equals(dataFromAppGallaryServer.getCodeSignature())) {
            if (dataFromAppGallaryServer.getMessage() != null) {
                LOGGER.error("Get code signature failed: {}", dataFromAppGallaryServer.getMessage());
            }
            return false;
        }
        return true;
    }

}
