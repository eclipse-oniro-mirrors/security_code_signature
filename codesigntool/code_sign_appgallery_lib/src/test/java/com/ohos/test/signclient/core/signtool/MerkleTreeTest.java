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

package com.ohos.codesigntool.core.fsverity;

import com.ohos.codesigntool.core.exception.FsVerityDigestException;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * MerkleTree Hash Test.
 *
 * @since 2023/06/27
 */
public class MerkleTreeTest {
    private static final String SMALL_UNFULL_CHUNK_SHA256_HASH =
        "e7295a358de9d164adc111e80f7e6298e9f5abe44e94f4fb181ac85267a200c6";

    private static final String SMALL_UNFULL_CHUNK_SHA512_HASH =
        "b4173cc4b36f910efac553871044ac9a211f7658cbf406711f7c1492116069f4" +
        "a30f04f03a21229da1df85201e1e2aa79ce40f8e1a95d82be3d522ea43a7b02b";

    private static final String MID_UNFULL_CHUNK_SHA256_HASH =
        "bcf7182fe7de3fb2076a648f95c09891fb050d318f09ce29e4c1e91b64ae92d2";

    private static final String MID_UNFULL_CHUNK_SHA512_HASH =
        "70f766c85a3cb4adec160668e1bbba68aa7e780414e147feb74cabce0e5aab60" +
        "08b7c9142a8a1392e5d39528feee666cc3b4456de11e76e8737e251f7fa66251";

    private static final String MID_FULL_CHUNK_SHA256_HASH =
        "4cba0ca57bb71fb3ab739499eb448cceaac3728edc15ce0984bb3ecadb8f43bb";

    private static final String MID_FULL_CHUNK_SHA512_HASH =
        "a623e2b24335507d35190e0dc750ad26f853ac8da75d1e0dcccca76b7634a0b0" +
        "5447f45a43376d75cc032b99364f97260a563be61fbdcd68c232fd326c817af0";

    /**
     * Test check small unfull chunk data sha256 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testSmallUnFullChunkSha256Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/4095file";
        checkFileHash(path, SMALL_UNFULL_CHUNK_SHA256_HASH, FsVerityHashAlgorithm.SHA256);
    }

    /**
     * Test check mid unfull chunk data sha256 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testMidUnFullChunkSha256Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/1000000file";
        checkFileHash(path, MID_UNFULL_CHUNK_SHA256_HASH, FsVerityHashAlgorithm.SHA256);
    }

    /**
     * Test check mid full chunk data sha256 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testMidFullChunkSha256Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/10485760file";
        checkFileHash(path, MID_FULL_CHUNK_SHA256_HASH, FsVerityHashAlgorithm.SHA256);
    }

    /**
     * Test check small unfull chunk data sha512 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testSmallUnFullChunkSha512Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/4095file";
        checkFileHash(path, SMALL_UNFULL_CHUNK_SHA512_HASH, FsVerityHashAlgorithm.SHA512);
    }

    /**
     * Test check mid unfull chunk data sha512 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testMidUnFullChunkSha512Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/1000000file";
        checkFileHash(path, MID_UNFULL_CHUNK_SHA512_HASH, FsVerityHashAlgorithm.SHA512);
    }

    /**
     * Test check mid full chunk data sha512 hash
     *
     * @throws FsVerityDigestException on error.
     */
    @Test
    public void testMidFullChunkSha512Hash() throws FsVerityDigestException {
        String path = "src/test/resources/hashtestfile/10485760file";
        checkFileHash(path, MID_FULL_CHUNK_SHA512_HASH, FsVerityHashAlgorithm.SHA512);
    }

    private void checkFileHash(String path, String hash, FsVerityHashAlgorithm fsVerityHashAlgorithm)
            throws FsVerityDigestException {
        MerkleTree merkleTree;
        try {
            File tempFile = new File(path);
            FileInputStream inputStream = new FileInputStream(tempFile);
            MerkleTreeBuilder builder = new MerkleTreeBuilder();
            merkleTree = builder.generateMerkleTree(inputStream, tempFile.length(), fsVerityHashAlgorithm);
            builder.close();
        } catch (IOException e) {
            throw new FsVerityDigestException("IOException" + e.getMessage(), e);
        }
        String stringHash = byte2hex(merkleTree.rootHash);
        Assert.assertEquals(stringHash, hash);
    }

    private String byte2hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        String tmp = null;
        for (byte b : bytes) {
            tmp = Integer.toHexString(0xFF & b);
            if (tmp.length() == 1) {
                tmp = "0" + tmp;
            }
            sb.append(tmp);
        }
        return sb.toString();
    }
}
