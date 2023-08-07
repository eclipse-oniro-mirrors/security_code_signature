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
 * class of data from App Gallary server.
 *
 * @since 2023/06/05
 */
public class DataFromAppGallaryServer {
    /**
     * AppGallary server signature result.
     */
    private String codeSignature;

    /**
     * AppGallary server message.
     */
    private String message;

    /**
     * json value of data from server of signcenter.
     */
    private DataFromSignCenterServer dataFromSignCenterServer;

    public String getCodeSignature() {
        return codeSignature;
    }

    public void setCodeSignature(String codeSignature) {
        this.codeSignature = codeSignature;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public DataFromSignCenterServer getDataFromSignCenterServer() {
        return dataFromSignCenterServer;
    }

    public void setDataFromSignCenterServer(DataFromSignCenterServer dataFromSignCenterServer) {
        this.dataFromSignCenterServer = dataFromSignCenterServer;
    }
}
