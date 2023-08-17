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

package com.ohos.codesigntool.core.signtool;

import com.ohos.codesigntool.core.api.CodeSignServer;
import com.ohos.codesigntool.core.provider.CodeSignProvider;
import com.ohos.codesigntool.core.provider.RemoteCodeSignProvider;

/**
 * code signature tool, defined function to sign hap file
 *
 * @since 2023/06/05
 */
public class CodeSignTool {
    private static final String CODE_SIGN_TOOL_VERSION = "V1.0";

    /**
     * code-signing API for hap file.
     *
     * @param server sign server interface provided by the caller.
     * @param params "-inputFile", "input file path",
     * "-outputPath", "output signature file path",
     * "-signAlg", "SHA256withECDSA",
     * "-outTree" , "true/false"
     * @return true, if sign successfully.
     */
    public static boolean signCode(CodeSignServer server, String[] params) {
        CodeSignProvider codeSignProvider = new RemoteCodeSignProvider();
        codeSignProvider.setCodeSignServer(server);
        return codeSignProvider.sign(params);
    }

    /**
     * Get version of tool.
     *
     * @return version of jar.
     */
    public static String getVersion() {
        return CODE_SIGN_TOOL_VERSION;
    }
}
