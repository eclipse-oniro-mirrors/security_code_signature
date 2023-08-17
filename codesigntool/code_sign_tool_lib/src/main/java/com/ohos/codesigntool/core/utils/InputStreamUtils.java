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

package com.ohos.codesigntool.core.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * InputStream util class
 *
 * @since 2023/08/10
 */
public class InputStreamUtils {
    private static final Logger LOGGER = LogManager.getLogger(InputStream.class);
    private static final int BUFFER_SIZE = 4096;

    /**
     * get byte array by inputStream and size
     *
     * @param inputStream inputStream data
     * @param inputStreamSize inputStream size
     * @return byte array value
     * @throws IOException io error
     */
    public static byte[] toByteArray(InputStream inputStream, int inputStreamSize) throws IOException {
        if (inputStreamSize == 0) {
            return new byte[0];
        }
        if (inputStreamSize < 0) {
            throw new IllegalArgumentException("inputStreamSize:" + inputStreamSize + " is less than zero: ");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        copy(inputStream, inputStreamSize, output);
        return output.toByteArray();
    }

    private static int copy(InputStream inputStream, int inputStreamSize, OutputStream output) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int readSize = 0;
        int count = 0;
        while (readSize < inputStreamSize && (readSize = inputStream.read(buffer)) != -1) {
            output.write(buffer, 0, readSize);
            count += readSize;
        }
        if (count != inputStreamSize) {
            throw new IOException("read size err. readSizeCount: " + count + ", inputStreamSize: " + inputStreamSize);
        }
        return count;
    }
}
