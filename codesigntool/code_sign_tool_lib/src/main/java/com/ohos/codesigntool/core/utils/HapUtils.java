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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * utility for check hap configs
 *
 * @since 2023/06/05
 */
public class HapUtils {
    /**
     * Represents the end-of-file.
     */
    public static final int EOF = -1;
    private static final Logger LOGGER = LogManager.getLogger(HapUtils.class);
    private static final String COMPRESS_NATIVE_LIBS_OPTION = "compressNativeLibs";
    private static final List<String> HAP_CONFIG_FILES = new ArrayList<String>();
    private static final String HAP_FA_CONFIG_JSON_FILE = "config.json";
    private static final String HAP_STAGE_MODULE_JSON_FILE = "module.json";
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    static {
        HAP_CONFIG_FILES.add(HAP_FA_CONFIG_JSON_FILE);
        HAP_CONFIG_FILES.add(HAP_STAGE_MODULE_JSON_FILE);
    }

    private HapUtils() {
    }

    private static byte[] toByteArray(final InputStream input, final int size) throws IOException {
        if (size < 0) {
            throw new IllegalArgumentException("Size must be equal or greater than zero: " + size);
        }

        if (size == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        final byte[] data = new byte[size];
        int offset = 0;
        int read;

        while (offset < size && (read = input.read(data, offset, size - offset)) != EOF) {
            offset += read;
        }

        if (offset != size) {
            throw new IOException("Unexpected read size. current: " + offset + ", expected: " + size);
        }

        return data;
    }

    /**
     * Check configuration in hap to find out whether the native libs are compressed
     *
     * @param hapFile the given hap
     * @return boolean value of parsing result
     * @throws IOException io error
     */
    public static boolean checkCompressNativeLibs(File hapFile) throws IOException {
        try (JarFile inputJar = new JarFile(hapFile, false)) {
            for (String configFile : HAP_CONFIG_FILES) {
                JarEntry entry = inputJar.getJarEntry(configFile);
                if (entry == null) {
                    continue;
                }
                try (InputStream data = inputJar.getInputStream(entry)) {
                    String jsonString = new String(toByteArray(data, (int) entry.getSize()), StandardCharsets.UTF_8);
                    return checkCompressNativeLibs(jsonString);
                }
            }
        }
        return true;
    }

    /**
     * Check whether the native libs are compressed by parsing config json
     *
     * @param jsonString the config json string
     * @return boolean value of parsing result
     */
    public static boolean checkCompressNativeLibs(String jsonString) {
        JsonObject jsonObject = JsonParser.parseString(jsonString).getAsJsonObject();
        Queue<JsonObject> queue = new LinkedList<>();
        queue.offer(jsonObject);
        while (queue.size() > 0) {
            JsonObject curJsonObject = queue.poll();
            JsonElement jsonElement = curJsonObject.get(COMPRESS_NATIVE_LIBS_OPTION);
            if (jsonElement != null) {
                return jsonElement.getAsBoolean();
            }
            for (Map.Entry<String, JsonElement> entry : curJsonObject.entrySet()) {
                if (entry.getValue().isJsonObject()) {
                    queue.offer(entry.getValue().getAsJsonObject());
                }

            }
        }
        // default to compress native libs
        return true;
    }
}
