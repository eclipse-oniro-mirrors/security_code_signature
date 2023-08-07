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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * util function about-file
 *
 * @since 2023/06/05
 */
public class FileUtils {
    private static final Logger LOGGER = LogManager.getLogger(FileUtils.class);

    /**
     * Check input file is valid.
     *
     * @param file input file.
     * @throws IOException file is not valid.
     */
    public static void isValid(File file) throws IOException {
        if (!file.exists()) {
            throw new FileNotFoundException(file + " does not exist");
        }

        if (file.isDirectory()) {
            throw new IOException(file + " is a directory");
        }

        if (!file.isFile()) {
            throw new IOException(file + " is not a file!");
        }

        if (!file.canRead()) {
            throw new IOException(file + " cannot be read");
        }
    }

    /**
     * Open an inputstream of input file safely.
     *
     * @param file input file.
     * @return file inputStream
     * @throws IOException file is a directory or can not be read.
     */
    public static FileInputStream open(File file) throws IOException {
        isValid(file);
        return new FileInputStream(file);
    }
}