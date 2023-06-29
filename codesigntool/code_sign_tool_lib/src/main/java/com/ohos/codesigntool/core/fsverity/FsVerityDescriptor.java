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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Format of FsVerity descriptor
 *
 * @since 2023/06/05
 */
public class FsVerityDescriptor {
    // Format
    // uint8 version
    // uint8 hashAlgorithm
    // uint8 log2BlockSize
    // uint8 saltSize
    // uint8[4] 0
    // le64 dataSize
    // uint8[64] rootHash
    // uint8[32] salt
    // uint8[144] 0

    private static final byte VERSION = 1;
    private static final int DESCRIPTOR_SIZE = 256;
    private static final int ROOT_HASH_FILED_SIZE = 64;
    private static final int SALT_SIZE = 32;
    private static final int FIRST_RESERVED_SIZE = 4;
    private static final int LAST_RESERVED_SIZE = 144;

    /**
     * Get FsVerity descriptor
     *
     * @param fileSize      size of input
     * @param hashAlgorithm hash algorithm id
     * @param log2BlockSize log2 of hash block size
     * @param salt          salt used for hash
     * @param rawRootHash   root hash of merkle tree
     * @return bytes of descriptor
     * @throws FsVerityDigestException if error
     */
    public static byte[] getDescriptor(long fileSize, byte hashAlgorithm, byte log2BlockSize,
                                       byte[] salt, byte[] rawRootHash) throws FsVerityDigestException {
        ByteBuffer buffer = ByteBuffer.allocate(DESCRIPTOR_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(VERSION);
        buffer.put(hashAlgorithm);
        buffer.put(log2BlockSize);
        if (salt == null) {
            buffer.put((byte) 0);
        } else if (salt.length > SALT_SIZE) {
            throw new FsVerityDigestException("Salt is too long");
        } else {
            buffer.put((byte) salt.length);
        }
        writeBytesWithSize(buffer, null, FIRST_RESERVED_SIZE);
        buffer.putLong(fileSize);
        writeBytesWithSize(buffer, rawRootHash, ROOT_HASH_FILED_SIZE);
        writeBytesWithSize(buffer, salt, SALT_SIZE);
        return buffer.array();
    }

    /**
     * Write bytes to ByteBuffer with specific size
     *
     * @param buffer target buffer
     * @param src    bytes to write
     * @param size   size of written bytes, fill 0 if src bytes is long enough
     */
    private static void writeBytesWithSize(ByteBuffer buffer, byte[] src, int size) {
        if (src != null) {
            if (src.length > size) {
                buffer.put(src, 0, size);
            } else {
                buffer.put(src);
            }
        }
        buffer.position(buffer.position() + size);
    }
}
