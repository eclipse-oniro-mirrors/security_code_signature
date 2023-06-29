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

package com.ohos.codesigntool.core.exception;

/**
 * Signature exception.
 *
 * @since 2023/06/05
 */
public class SignatureException extends Exception {
    private static final long serialVersionUID = -281871003709431259L;

    private int errorCode;

    /**
     * SignatureException
     *
     * @param message msg
     */
    public SignatureException(String message) {
        super(message);
    }

    /**
     * SignatureException
     *
     * @param errorCode code
     * @param message msg
     */
    public SignatureException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * SignatureException
     *
     * @param errorCode code
     * @param message msg
     * @param cause cause
     */
    public SignatureException(int errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * SignatureException
     *
     * @param message msg
     * @param cause cause
     */
    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public String getMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("errorcode:");
        sb.append(this.errorCode);
        sb.append(",");
        sb.append("message:");
        sb.append(super.getMessage());
        sb.append("}");
        return sb.toString();
    }
}
