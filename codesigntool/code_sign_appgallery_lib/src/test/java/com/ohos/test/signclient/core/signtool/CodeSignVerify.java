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

package com.ohos.test.signclient.core.signtool;

import com.ohos.codesigntool.core.exception.FsVerityDigestException;
import com.ohos.codesigntool.core.fsverity.FsVerityGenerator;
import com.ohos.codesigntool.core.utils.CmsUtils;
import com.ohos.codesigntool.core.utils.InputStreamUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * HapSigVerify.
 *
 * @since 2023/07/1
 */
public class CodeSignVerify {
    private static final Logger LOGGER = LogManager.getLogger(CodeSignVerify.class);
    private static final String SO_SUFFIX = ".so";
    private static final String AN_SUFFIX = ".an";
    private static final String SINGLE_SIG_SUFFIX = ".fsv-sig";
    private static final String HAP_SIGNATURE_ENTRY_NAME = "Hap";
    private static final List<String> EXTRACTED_NATIVE_LIB_SUFFIXS = new ArrayList<>();
    private static final List<String> EXTRACTED_SIG_SUFFIXS = new ArrayList<>();

    static {
        EXTRACTED_NATIVE_LIB_SUFFIXS.add(AN_SUFFIX);
        EXTRACTED_NATIVE_LIB_SUFFIXS.add(SO_SUFFIX);
        EXTRACTED_SIG_SUFFIXS.add(SINGLE_SIG_SUFFIX);
    }

    private Map<String, byte[]> mapHapData = new HashMap<String, byte[]>();
    private Map<String, byte[]> mapSignData = new HashMap<String, byte[]>();

    /**
     * Verify binary files contained within the file
     *
     * @param hapPath          input hap file path
     * @param signPath         input sign file path
     * @return                 verify result
     */
    public boolean verifyCode(String hapPath, String signPath) {
        boolean verifyCode = false;
        try {
            generateMapData(new File(hapPath), false);
            generateMapData(new File(signPath), true);
            verifyCode = verifyMapData();
        } catch (CMSException | IOException | FsVerityDigestException e) {
            LOGGER.error("verify code failed!", e);
        }
        return verifyCode;
    }

    private void generateMapData(File file, boolean isSignFile)throws IOException, FsVerityDigestException {
        if (isSignFile) {
            mapSignData.clear();
        } else {
            mapHapData.clear();
            try (FileInputStream inputStream = new FileInputStream(file)) {
                mapHapData.put(HAP_SIGNATURE_ENTRY_NAME,
                    generateFsVerityDigest(inputStream, file.length()));
            }
        }
        try (JarFile inputJar = new JarFile(file, false)) {
            List<String> entryNames = getTargetEntries(inputJar, isSignFile);
            if (entryNames.isEmpty()) {
                return;
            }
            if (isSignFile) {
                generateMapSignData(entryNames, inputJar);
            } else {
                generateMapHapData(entryNames, inputJar);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void generateMapHapData(List<String> entryNames, JarFile hap) throws IOException, FsVerityDigestException {
        for (String name : entryNames) {
            JarEntry inEntry = hap.getJarEntry(name);
            try (InputStream inputStream = hap.getInputStream(inEntry)) {
                mapHapData.put(name, generateFsVerityDigest(inputStream, inEntry.getSize()));
            }
        }
    }

    private byte[] generateFsVerityDigest(InputStream inputStream, long size) throws FsVerityDigestException {
        FsVerityGenerator fsVerityGenerator = new FsVerityGenerator();
        fsVerityGenerator.generateFsVerityDigest(inputStream, size);
        return fsVerityGenerator.getFsVerityDigest();
    }

    private void generateMapSignData(List<String> entryNames, JarFile hap) throws IOException, FsVerityDigestException {
        for (String name : entryNames) {
            JarEntry inEntry = hap.getJarEntry(name);
            try (InputStream data = hap.getInputStream(inEntry)) {
                byte[] signDigest = InputStreamUtils.toByteArray(data, (int) inEntry.getSize());
                mapSignData.put(name, signDigest);
            }
        }
    }

    private boolean verifyMapData() throws CMSException {
        for (Map.Entry<String, byte[]> entry : mapSignData.entrySet()) {
            String signKey = entry.getKey();
            int index = signKey.indexOf(SINGLE_SIG_SUFFIX);
            if (index == -1) {
                throw new CMSException("Sign file name err:" + signKey);
            }
            String hapKey = signKey.substring(0, index);
            boolean verifyResult = CmsUtils.verifySignDataWithUnsignedDataDigest(
                mapHapData.get(hapKey), entry.getValue());
            if (!verifyResult) {
                throw new CMSException("PKCS cms data did not verify");
            }
        }
        return true;
    }

    private List<String> getTargetEntries(JarFile file, boolean isSignFile) {
        List<String> result = new ArrayList<>();
        for (Enumeration<JarEntry> e = file.entries(); e.hasMoreElements();) {
            JarEntry entry = e.nextElement();
            if (!entry.isDirectory()) {
                if (!isTargetType(entry.getName(), isSignFile)) {
                    continue;
                }
                result.add(entry.getName());
            }
        }
        return result;
    }

    private boolean isTargetType(String entryName, boolean isSignFile) {
        List<String> stringList;
        if (isSignFile) {
            stringList = EXTRACTED_SIG_SUFFIXS;
        } else {
            stringList = EXTRACTED_NATIVE_LIB_SUFFIXS;
        }
        for (String suffix : stringList) {
            if (entryName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }
}
