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
 * Exception occurs when the required parameters are not entered.
 *
 * @since 2023/06/05
 */
public class MissingParamsException extends Exception {

    private static final long serialVersionUID = -8922730964374794468L;

    /**
     * Exception occurs when the required parameters are not entered.
     *
     * @param message msg
     */
    public MissingParamsException(String message) {
        super(message);
    }

    /**
     * Exception occurs when the required parameters are not entered.
     *
     * @param message msg
     * @param cause cause
     */
    public MissingParamsException(String message, Throwable cause) {
        super(message, cause);
    }
}
