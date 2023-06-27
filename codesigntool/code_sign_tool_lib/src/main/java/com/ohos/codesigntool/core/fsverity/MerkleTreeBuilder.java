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
import com.ohos.codesigntool.core.utils.DigestUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Phaser;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Merkle tree builder
 *
 * @since 2023/06/19
 */
public class MerkleTreeBuilder {
    private static final Logger LOGGER = LogManager.getLogger(MerkleTreeBuilder.class);

    private static final int FSVERITY_HASH_PAGE_SIZE = 4096;

    private static final long INPUTSTREAM_MAX_SIZE = 4503599627370496L;

    private static final long CHUNK_SIZE = 4096L;

    private static final long MAX_READ_SIZE = 4194304L;

    private static final int MAX_PROCESSORS = 32;

    private static final int BLOCKINGQUEUE = 4;

    private static final int POOL_SIZE = Math.min(MAX_PROCESSORS,
        Runtime.getRuntime().availableProcessors());

    private String mAlgorithm = "SHA-256";

    private final ExecutorService mPools = new ThreadPoolExecutor(POOL_SIZE, POOL_SIZE, 0L,
        TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(BLOCKINGQUEUE),
        new ThreadPoolExecutor.CallerRunsPolicy());

    /**
     * Turn off multitasking
     */
    public void close() {
        this.mPools.shutdownNow();
    }

    /**
     * set algorithm
     *
     * @param algorithm              hash algorithm
     */
    private void setAlgorithm(String algorithm) {
        this.mAlgorithm = algorithm;
    }

    /**
     * translation inputStream to ByteBuffer
     *
     * @param inputStream              input stream for generating merkle tree
     * @param size                     total size of input stream
     * @return                         ByteBuffer data
     * @throws IOException             if error
     * @throws FsVerityDigestException if error
     */
    private ByteBuffer[] convertToByteBuffer(InputStream inputStream, long size)
            throws IOException, FsVerityDigestException {
        if (size == 0) {
            throw new FsVerityDigestException("Input size is empty");
        } else if (size > INPUTSTREAM_MAX_SIZE) {
            throw new FsVerityDigestException("Input size is too long");
        }
        int count = (int) getChunkCount(size, MAX_READ_SIZE);
        ByteBuffer[] byteBuffer = new ByteBuffer[count];
        long readOffset = 0L;
        for (int i = 0; i < count; i++) {
            long readLimit = Math.min(readOffset + MAX_READ_SIZE, size);
            int readSize = (int) (readLimit - readOffset);
            int fullChunkSize = (int) getFullChunkSize(readSize, CHUNK_SIZE, CHUNK_SIZE);
            byteBuffer[i] = ByteBuffer.allocate(fullChunkSize);
            int offset = 0;
            byte[] buffer = new byte[(int) CHUNK_SIZE];
            int num;
            while ((num = inputStream.read(buffer)) > 0) {
                byteBuffer[i].put(buffer, 0, num);
                offset += num;
                if (offset >= fullChunkSize || offset == readSize) {
                    break;
                }
            }
            if (offset != readSize) {
                throw new FsVerityDigestException("IOException read buffer from input error.");
            }
            byteBuffer[i].flip();
            readOffset += readSize;
        }
        return byteBuffer;
    }

    /**
     * split buffer by begin and end information
     *
     * @param buffer              original buffer
     * @param begin               begin position
     * @param end                 end position
     * @return                    slice buffer
     */
    private static ByteBuffer slice(ByteBuffer buffer, int begin, int end) {
        ByteBuffer tempBuffer = buffer.duplicate();
        tempBuffer.position(0);
        tempBuffer.limit(end);
        tempBuffer.position(begin);
        return tempBuffer.slice();
    }

    /**
     * calculate merkle tree level and size by data size and digest size
     *
     * @param dataSize              original data size
     * @param digestSize            algorithm data size
     * @return                      level offset list,contains the offset of
     * each level from the root node to the leaf node
     */
    private static int[] getOffsetArrays(long dataSize, int digestSize) {
        ArrayList<Long> levelSize = getlevelSize(dataSize, digestSize);
        int[] levelOffset = new int[levelSize.size() + 1];
        levelOffset[0] = 0;
        for (int i = 0; i < levelSize.size(); i++) {
            levelOffset[i + 1] = levelOffset[i] + Math.toIntExact((
                levelSize.get(levelSize.size() - i - 1)).longValue());
        }
        return levelOffset;
    }

    /**
     * calculate data size list by data size and digest size
     *
     * @param dataSize              original data size
     * @param digestSize            algorithm data size
     * @return                      data size list,contains the offset of
     * each level from the root node to the leaf node
     */
    private static ArrayList<Long> getlevelSize(long dataSize, int digestSize) {
        ArrayList<Long> levelSize = new ArrayList<>();
        long fullChunkSize = 0L;
        long originalDataSize = dataSize;
        do {
            fullChunkSize = getFullChunkSize(originalDataSize, CHUNK_SIZE, digestSize);
            long size = getFullChunkSize(fullChunkSize, CHUNK_SIZE, CHUNK_SIZE);
            levelSize.add(Long.valueOf(size));
            originalDataSize = fullChunkSize;
        } while (fullChunkSize > CHUNK_SIZE);
        return levelSize;
    }

    /**
     * encrypted data
     *
     * @param inputBuffer              original data
     * @param size                     total size of input stream
     * @param outputBuffer             hash data
     * @throws FsVerityDigestException if error
     */
    private void transInputDataToHashData(ByteBuffer[] inputBuffer, long size, ByteBuffer outputBuffer)
            throws FsVerityDigestException {
        int count = inputBuffer.length;
        int chunks = (int) getChunkCount(size, CHUNK_SIZE);
        byte[][] hashes = new byte[chunks][];
        Phaser tasks = new Phaser(1);
        for (int i = 0; i < count; i++) {
            ByteBuffer buffer = inputBuffer[i];
            buffer.rewind();
            int readChunkIndex = (int) getFullChunkSize(MAX_READ_SIZE, CHUNK_SIZE, i);
            Runnable task = () -> {
                int offset = 0;
                int bufferSize = buffer.capacity();
                int index = readChunkIndex;
                while (offset < bufferSize) {
                    ByteBuffer chunk = slice(buffer, offset, offset + (int) CHUNK_SIZE);
                    byte[] tempByte = new byte[(int) CHUNK_SIZE];
                    chunk.get(tempByte);
                    hashes[index++] = DigestUtils.computeDigest(tempByte, this.mAlgorithm);
                    offset += (int) CHUNK_SIZE;
                }
                tasks.arriveAndDeregister();
            };
            tasks.register();
            this.mPools.execute(task);
        }
        tasks.arriveAndAwaitAdvance();
        for (byte[] hash : hashes) {
            outputBuffer.put(hash, 0, hash.length);
        }
    }

    /**
     * encrypted data
     *
     * @param inputBuffer              original data
     * @param outputBuffer             hash data
     * @throws FsVerityDigestException if error
     */
    private void transInputDataToHashData(ByteBuffer inputBuffer, ByteBuffer outputBuffer)
            throws FsVerityDigestException {
        long size = inputBuffer.capacity();
        int chunks = (int) getChunkCount(size, CHUNK_SIZE);
        byte[][] hashes = new byte[chunks][];
        Phaser tasks = new Phaser(1);
        long readOffset = 0L;
        int startChunkIndex = 0;
        while (readOffset < size) {
            long readLimit = Math.min(readOffset + MAX_READ_SIZE, size);
            ByteBuffer buffer = slice(inputBuffer, (int) readOffset, (int) readLimit);
            buffer.rewind();
            int readChunkIndex = startChunkIndex;
            Runnable task = () -> {
                int offset = 0;
                int bufferSize = buffer.capacity();
                int index = readChunkIndex;
                while (offset < bufferSize) {
                    ByteBuffer chunk = slice(buffer, offset, offset + (int) CHUNK_SIZE);
                    byte[] tempByte = new byte[(int) CHUNK_SIZE];
                    chunk.get(tempByte);
                    hashes[index++] = DigestUtils.computeDigest(tempByte, this.mAlgorithm);
                    offset += (int) CHUNK_SIZE;
                }
                tasks.arriveAndDeregister();
            };
            tasks.register();
            this.mPools.execute(task);
            int readSize = (int) (readLimit - readOffset);
            startChunkIndex += (int) getChunkCount(readSize, CHUNK_SIZE);
            readOffset += readSize;
        }
        tasks.arriveAndAwaitAdvance();
        for (byte[] hash : hashes) {
            outputBuffer.put(hash, 0, hash.length);
        }
    }

    /**
     * generate merkle tree of given input
     *
     * @param inputStream              input stream for generating merkle tree
     * @param size                     total size of input stream
     * @param fsVerityHashAlgorithm    hash algorithm for FsVerity
     * @return                         merkle tree
     * @throws FsVerityDigestException if error
     */
    public MerkleTree generateMerkleTree(InputStream inputStream, long size,
            FsVerityHashAlgorithm fsVerityHashAlgorithm) throws FsVerityDigestException {
        setAlgorithm(fsVerityHashAlgorithm.getHashAlgorithm());
        int digestSize = fsVerityHashAlgorithm.getOutputByteSize();
        int[] offsetArrays = getOffsetArrays(size, digestSize);
        ByteBuffer allHashBuffer = ByteBuffer.allocate(offsetArrays[offsetArrays.length - 1]);
        generateHashDataByInputData(inputStream, size, allHashBuffer, offsetArrays, digestSize);
        generateHashDataByHashData(allHashBuffer, offsetArrays, digestSize);
        return getMerkleTree(allHashBuffer, size, fsVerityHashAlgorithm);
    }

    /**
     * translation inputBuffer arrays to hash ByteBuffer
     *
     * @param inputStream              input stream for generating merkle tree
     * @param size                     total size of input stream
     * @param outputBuffer             hash data
     * @param offsetArrays             level offset
     * @param digestSize               algorithm output byte size
     * @throws FsVerityDigestException if error
     */
    private void generateHashDataByInputData(InputStream inputStream, long size, ByteBuffer outputBuffer,
            int[] offsetArrays, int digestSize) throws FsVerityDigestException {
        int inputDataOffsetBegin = offsetArrays[offsetArrays.length - 2];
        int inputDataOffsetEnd = offsetArrays[offsetArrays.length - 1];
        long inputDataBufferSize = 0L;
        ByteBuffer hashBuffer = slice(outputBuffer, inputDataOffsetBegin, inputDataOffsetEnd);
        ByteBuffer[] inputBuffer;
        try {
            inputBuffer = convertToByteBuffer(inputStream, size);
            for (ByteBuffer tempinputBuffer : inputBuffer) {
                inputDataBufferSize += tempinputBuffer.capacity();
            }
        } catch (IOException e) {
            throw new FsVerityDigestException("IOException" + e.getMessage(), e);
        }
        transInputDataToHashData(inputBuffer, inputDataBufferSize, hashBuffer);
        dataRoundupChunkSize(hashBuffer, inputDataBufferSize, digestSize);
    }

    /**
     * get buffer data by level offset,transforms digest data,save in another memory
     *
     * @param buffer                   hash data
     * @param offsetArrays             level offset
     * @param digestSize               algorithm output byte size
     * @throws FsVerityDigestException if error
     */
    private void generateHashDataByHashData(ByteBuffer buffer, int[] offsetArrays,
            int digestSize) throws FsVerityDigestException {
        for (int i = offsetArrays.length - 3; i >= 0; i--) {
            ByteBuffer generateHashBuffer = slice(buffer, offsetArrays[i], offsetArrays[i + 1]);
            ByteBuffer originalHashBuffer = slice(buffer.asReadOnlyBuffer(),
                offsetArrays[i + 1], offsetArrays[i + 2]);
            transInputDataToHashData(originalHashBuffer, generateHashBuffer);
            dataRoundupChunkSize(generateHashBuffer, originalHashBuffer.capacity(), digestSize);
        }
    }

    /**
     * generate merkle tree of given input
     *
     * @param dataBuffer               tree data memory block
     * @param inputDataSize            total size of input stream
     * @param fsVerityHashAlgorithm    hash algorithm for FsVerity
     * @return                         merkle tree
     * @throws FsVerityDigestException if error
     */
    private MerkleTree getMerkleTree(ByteBuffer dataBuffer, long inputDataSize,
            FsVerityHashAlgorithm fsVerityHashAlgorithm) throws FsVerityDigestException {
        int digestSize = fsVerityHashAlgorithm.getOutputByteSize();
        dataBuffer.flip();
        byte[] rootHash = null;
        byte[] tree = null;
        if (inputDataSize < FSVERITY_HASH_PAGE_SIZE) {
            ByteBuffer fsVerityHashPageBuffer = slice(dataBuffer, 0, digestSize);
            rootHash = new byte[digestSize];
            fsVerityHashPageBuffer.get(rootHash);
        } else {
            tree = dataBuffer.array();
            ByteBuffer fsVerityHashPageBuffer = slice(dataBuffer.asReadOnlyBuffer(), 0, FSVERITY_HASH_PAGE_SIZE);
            byte[] fsVerityHashPage = new byte[FSVERITY_HASH_PAGE_SIZE];
            fsVerityHashPageBuffer.get(fsVerityHashPage);
            rootHash = DigestUtils.computeDigest(fsVerityHashPage, this.mAlgorithm);
        }
        return new MerkleTree(rootHash, tree, fsVerityHashAlgorithm);
    }

    /**
     * generate merkle tree of given input
     *
     * @param data               original data
     * @param originalDataSize   data size
     * @param digestSize         algorithm output byte size
     */
    private void dataRoundupChunkSize(ByteBuffer data, long originalDataSize, int digestSize) {
        long fullChunkSize = getFullChunkSize(originalDataSize, CHUNK_SIZE, digestSize);
        int diffValue = (int) (fullChunkSize % CHUNK_SIZE);
        if (diffValue > 0) {
            byte[] padding = new byte[(int) CHUNK_SIZE - diffValue];
            data.put(padding, 0, padding.length);
        }
    }

    /**
     * get satisfy need minimum data chunk
     *
     * @param dataSize              data size
     * @param divisor               split chunk size
     * @return                      chunk
     */
    private static long getChunkCount(long dataSize, long divisor) {
        return (long) Math.ceil((double) dataSize / (double) divisor);
    }

    /**
     * get satisfy need minimum data chunk
     *
     * @param dataSize              data size
     * @param divisor               split chunk size
     * @param multiplier            chunk multiplier
     * @return                      chunk size
     */
    private static long getFullChunkSize(long dataSize, long divisor, long multiplier) {
        return getChunkCount(dataSize, divisor) * multiplier;
    }
}
