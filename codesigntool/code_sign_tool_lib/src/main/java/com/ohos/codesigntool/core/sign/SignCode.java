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

package com.ohos.codesigntool.core.sign;

import com.ohos.codesigntool.core.config.CodeSignConfig;
import com.ohos.codesigntool.core.config.RemoteCodeSignConfig;
import com.ohos.codesigntool.core.exception.FsVerityDigestException;
import com.ohos.codesigntool.core.exception.CodeSignException;
import com.ohos.codesigntool.core.fsverity.FsVerityGenerator;
import com.ohos.codesigntool.core.utils.HapUtils;

import com.ohos.codesigntool.core.utils.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * core functions to sign code
 *
 * @since 2023/06/05
 */
public class SignCode {
    private static final Logger LOGGER = LogManager.getLogger(SignCode.class);
    private static final int COMPRESSION_MODE = 9;
    private static final String HAP_SIGNATURE_ENTRY_NAME = "Hap";
    private static final String SIGNATURE_FILE_SUFFIX = ".fsv-sig";
    private static final String MERKLE_TREE_FILE_SUFFIX = ".fsv-tree";
    private static final String NATIVE_LIB_AN_SUFFIX = ".an";
    private static final String NATIVE_LIB_SO_SUFFIX = ".so";
    private static final List<String> EXTRACTED_NATIVE_LIB_SUFFIXS = new ArrayList<>();

    static {
        EXTRACTED_NATIVE_LIB_SUFFIXS.add(NATIVE_LIB_AN_SUFFIX);
        EXTRACTED_NATIVE_LIB_SUFFIXS.add(NATIVE_LIB_SO_SUFFIX);
    }

    private final CodeSignConfig signConfig;
    private long timestamp = 0L;

    /**
     * provide code sign functions to sign a hap
     *
     * @param signConfig configuration of signer
     */
    public SignCode(CodeSignConfig signConfig) {
        this.signConfig = signConfig;
    }

    /**
     * Sign the given hap file, and pack all signature into output file
     *
     * @param input     file to sign
     * @param output    returned signature file
     * @param storeTree determine whether merkle tree is also output in signature file
     * @throws IOException             io error
     * @throws FsVerityDigestException computing FsVerity digest error
     * @throws CodeSignException      signing error
     */
    public void signCode(File input, File output, boolean storeTree)
        throws IOException, FsVerityDigestException, CodeSignException {
        LOGGER.info("Start to sign code.");
        try (FileOutputStream outputFile = new FileOutputStream(output);
            ZipOutputStream outputZip = new ZipOutputStream(outputFile)) {
            timestamp = System.currentTimeMillis();
            outputZip.setLevel(COMPRESSION_MODE);

            LOGGER.debug("Sign hap.");
            try (FileInputStream inputStream = new FileInputStream(input)) {
                signFileAndAddToZip(inputStream, input.length(), HAP_SIGNATURE_ENTRY_NAME, outputZip, storeTree);
            }

            // no need to sign native files if libs are not extracted
            if (!HapUtils.checkCompressNativeLibs(input)) {
                LOGGER.info("No need to sign native libs.");
                return;
            }

            // sign native files
            try (JarFile inputJar = new JarFile(input, false)) {
                List<String> entryNames = getNativeEntriesFromHap(inputJar);
                if (entryNames.isEmpty()) {
                    LOGGER.info("No native libs.");
                    return;
                }
                signFilesFromJar(entryNames, inputJar, outputZip, storeTree);
            }
        }
        LOGGER.info("Sign successfully.");
    }

    /**
     * Sign a single file with given inputStream
     *
     * @param inputStream input stream
     * @param fileSize    file size of the target file
     * @param entryName   the origin entry name of file in hap
     * @param outputZip   output zip which packs the generated signature
     * @param storeTree   determine whether merkle tree is also output
     * @throws IOException             io error
     * @throws FsVerityDigestException computing FsVerity digest error
     * @throws CodeSignException      signing error
     */
    private void signFileAndAddToZip(InputStream inputStream, long fileSize, String entryName,
            ZipOutputStream outputZip, boolean storeTree)
        throws IOException, FsVerityDigestException, CodeSignException {
        Pair<byte[], byte[]> result = signFile(inputStream, fileSize);
        addEntryToZip(result.getKey(), entryName + SIGNATURE_FILE_SUFFIX, outputZip);
        if (storeTree) {
            addEntryToZip(result.getValue(), entryName + MERKLE_TREE_FILE_SUFFIX, outputZip);
        }

    }

    private void addEntryToZip(byte[] data, String entryName, ZipOutputStream outputZip)
            throws IOException {
        ZipEntry entry = new ZipEntry(entryName);
        entry.setTime(timestamp);
        outputZip.putNextEntry(entry);
        outputZip.write(data, 0, data.length);
        outputZip.flush();
    }

    /**
     * Get entry name of all native files in hap
     *
     * @param hap the given hap
     * @return list of entry name
     */
    private List<String> getNativeEntriesFromHap(JarFile hap) {
        List<String> result = new ArrayList<>();
        for (Enumeration<JarEntry> e = hap.entries(); e.hasMoreElements();) {
            JarEntry entry = e.nextElement();
            if (!entry.isDirectory()) {
                if (!isNativeFile(entry.getName())) {
                    continue;
                }
                result.add(entry.getName());
            }
        }
        return result;
    }

    /**
     * Check whether the entry is a native file
     *
     * @param entryName the name of entry
     * @return true if it is a native file, and false otherwise
     */
    private boolean isNativeFile(String entryName) {
        for (String suffix : EXTRACTED_NATIVE_LIB_SUFFIXS) {
            if (entryName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sign specific entries in a hap
     *
     * @param entryNames list of entries which need to be signed
     * @param hap        input hap
     * @param outputZip  output zip which packs the generated signature
     * @param storeTree  determine whether merkle tree is also output
     * @throws IOException             io error
     * @throws FsVerityDigestException computing FsVerity digest error
     * @throws CodeSignException      signing error
     */
    public void signFilesFromJar(List<String> entryNames, JarFile hap, ZipOutputStream outputZip, boolean storeTree)
            throws IOException, FsVerityDigestException, CodeSignException {
        for (String name : entryNames) {
            LOGGER.debug("Sign entry name = " + name);
            JarEntry inEntry = hap.getJarEntry(name);
            try (InputStream inputStream = hap.getInputStream(inEntry)) {
                long fileSize = inEntry.getSize();
                signFileAndAddToZip(inputStream, fileSize, name, outputZip, storeTree);
            }
        }
    }

    /**
     * Sign a file from input stream
     *
     * @param inputStream input stream of a file
     * @param fileSize    size of the file
     * @return pair of signature and tree
     * @throws FsVerityDigestException computing FsVerity Digest error
     * @throws CodeSignException      signing error
     */
    public Pair<byte[], byte[]> signFile(InputStream inputStream, long fileSize)
            throws FsVerityDigestException, CodeSignException {
        FsVerityGenerator fsVerityGenerator = new FsVerityGenerator();
        fsVerityGenerator.generateFsVerityDigest(inputStream, fileSize);
        byte[] fsVerityDigest = fsVerityGenerator.getFsVerityDigest();
        byte[] signature = generateSignature(fsVerityDigest);
        return Pair.create(signature, fsVerityGenerator.getTreeBytes());
    }

    private byte[] generateSignature(byte[] signedData) throws CodeSignException {
        if (!(signConfig instanceof RemoteCodeSignConfig)) {
            if (signConfig.getCertificates().isEmpty()) {
                throw new CodeSignException("No certificates configured for signer");
            }
        }
        return SignedDataGenerator.BC.generateSignedData(signedData, signConfig);
    }

}