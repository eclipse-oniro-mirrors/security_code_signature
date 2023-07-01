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

import com.ohos.codesigntool.core.signtool.CodeSignTool;
import com.ohos.codesigntool.core.utils.ParamConstants;
import com.ohos.test.signclient.core.api.TestCodeSignServer;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * CodeSignTool Tester.
 *
 * @since 2023/06/05
 */
public class CodeSignToolTest {
    private static final String SEPARATOR = File.separator;
    private static final File TMP_DIR = new File("target");
    private static final int MIN_DATA_CHUNK_SIZE = 4096;
    private static final int MAX_DATA_CHUNK_SIZE = 1024 * 1024 * 2;
    private static final int MIN_ENTRY_COUNT = 1;
    private static final int MAX_ENTRY_COUNT = 16;
    private static final int CONCURRENT_TASK_COUNT = 10;
    private static final int CONCURRENT_TASK_EXECUTE_TIME = 30;
    private static final int CONCURRENT_TASK_TYPE_HAP = 1;
    private static final String DEFAULT_SIGN_ALG = "SHA256withECDSA";
    private static final String TMP_UNSIGNED_FILE_PREFIX = "unsigned-";
    private static final String TMP_SIGNED_FILE_PREFIX = "signed-";
    private static final String TMP_HAP_FILE_SUFFIX = ".hap";
    private static final String OUTPUT_MERKLE_TREE = "true";
    private static final String TEST_TARGET_HAPS_BASE =
            "src" + SEPARATOR + "test" + SEPARATOR + "resources" + SEPARATOR + "haps";
    private static final List<String> MODULE_TYPES = new ArrayList<>();
    private static final String STAGE_MODULE = "STAGE";
    private static final String FA_MODULE = "FA";
    private static final List<String> COMPRESS_NATIVE_LIB_OPTIONS = new ArrayList<>();
    private static final String TRUE_OPTION = "true";
    private static final String FALSE_OPTION = "false";
    private static final String NONE_OPTION = "none";
    private static final Map<String, Boolean> OPTIONS_AND_LIB_SIGNATURE_MAP = new HashMap<>();
    private static final String SO_SUFFIX = ".so";
    private static final String HAP_SUFFIX = ".hap";
    private static final String SIG_SUFFIX = ".sig";
    private static final String SINGLE_SIG_SUFFIX = ".fsv-sig";
    private static List<Cleanable> tmpSources;
    private static String tmpOutputPath;

    static {
        MODULE_TYPES.add(STAGE_MODULE);
        MODULE_TYPES.add(FA_MODULE);
        COMPRESS_NATIVE_LIB_OPTIONS.add(TRUE_OPTION);
        COMPRESS_NATIVE_LIB_OPTIONS.add(FALSE_OPTION);
        COMPRESS_NATIVE_LIB_OPTIONS.add(NONE_OPTION);
        OPTIONS_AND_LIB_SIGNATURE_MAP.put(TRUE_OPTION, true);
        OPTIONS_AND_LIB_SIGNATURE_MAP.put(FALSE_OPTION, false);
        OPTIONS_AND_LIB_SIGNATURE_MAP.put(NONE_OPTION, true);
    }

    /**
     * Init template resources container.
     */
    @BeforeClass
    public static void initTmpResourcesContainer() {
        tmpSources = new CopyOnWriteArrayList<>();
        try {
            tmpOutputPath = Files.createTempDirectory(TMP_DIR.toPath(), TMP_SIGNED_FILE_PREFIX).toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Clean template resources.
     */
    @AfterClass
    public static void cleanTmpResources() {
        tmpSources.forEach(Cleanable::clean);
        File dir = new File(tmpOutputPath);
        File[] files = dir.listFiles();
        for (File file : files) {
            file.delete();
        }
        dir.delete();
    }

    /**
     * Test sign hap.
     *
     * @throws Exception on error.
     */
    @Test
    public void testSignHap() throws Exception {
        File unsignedHap = File.createTempFile(TMP_UNSIGNED_FILE_PREFIX, TMP_HAP_FILE_SUFFIX, TMP_DIR);
        tmpSources.add(new CleanableFile(unsignedHap));
        testSignCode(unsignedHap, true);
    }

    /**
     * Test sign file that does not exist.
     *
     * @throws Exception on error.
     */
    @Test
    public void testInvalidInputFile() throws Exception {
        Params param = new Params();
        param.addParam(ParamConstants.PARAM_BASIC_INPUT_FILE, "invalid");
        param.addParam(ParamConstants.PARAM_BASIC_OUTPUT_PATH, tmpOutputPath);
        param.addParam(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, DEFAULT_SIGN_ALG);

        String[] params = param.toArray();
        TestCodeSignServer server = new TestCodeSignServer();
        Assert.assertFalse("sign nonexistent file", CodeSignTool.signCode(server, params));
    }

    /**
     * Test sign and store merkle tree in ouput file.
     *
     * @throws Exception on error
     */
    @Test
    public void testSignHapAndStoreTree() throws Exception {
        testSignCodeWithTree();
    }

    /**
     * Test sign code on multi-thread.
     *
     * @throws Exception on error
     */
    @Test
    public void testSignCodeConcurrent() throws Exception {
        executeConcurrentTask(CONCURRENT_TASK_TYPE_HAP);
    }

    private void executeConcurrentTask(int taskType) throws Exception {
        CountDownLatch countDownLatch = new CountDownLatch(CONCURRENT_TASK_COUNT);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(CONCURRENT_TASK_COUNT,
                CONCURRENT_TASK_COUNT, 30, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(CONCURRENT_TASK_COUNT),
                new ThreadPoolExecutor.CallerRunsPolicy());
        List<Future<Boolean>> futures = new ArrayList<>(CONCURRENT_TASK_COUNT);
        List<Callable<Boolean>> tasks = new ArrayList<>(CONCURRENT_TASK_COUNT);
        for (int i = 0; i < CONCURRENT_TASK_COUNT; i++) {
            if (taskType == CONCURRENT_TASK_TYPE_HAP) {
                tasks.add(generateSignCodeTask(countDownLatch));
            }
        }
        for (Callable<Boolean> task : tasks) {
            Future<Boolean> future = executor.submit(task);
            futures.add(future);
        }
        executor.shutdown();
        boolean isFinished = countDownLatch.await(CONCURRENT_TASK_EXECUTE_TIME, TimeUnit.SECONDS);
        if (!isFinished) {
            executor.shutdownNow();
        }
        Assert.assertTrue("some task not finished in " + CONCURRENT_TASK_EXECUTE_TIME + "seconds.", isFinished);
        for (Future<Boolean> future : futures) {
            Boolean isSuccess = future.get();
            Assert.assertNotNull("task not finish or error", isSuccess);
            Assert.assertTrue("task failed", isSuccess);
        }
    }

    private Callable<Boolean> generateSignCodeTask(CountDownLatch countDownLatch) throws IOException {
        File inputFile = File.createTempFile(TMP_UNSIGNED_FILE_PREFIX, TMP_HAP_FILE_SUFFIX, TMP_DIR);
        tmpSources.add(new CleanableFile(inputFile));
        fillHapFile(inputFile);
        return new MultiSignCodeTask(inputFile, tmpOutputPath, countDownLatch);
    }


    private void testSignCode(File unsignedHap, boolean fill) throws Exception {
        if (fill) {
            fillHapFile(unsignedHap);
        }

        Params param = new Params();
        param.addParam(ParamConstants.PARAM_BASIC_INPUT_FILE, unsignedHap.getPath());
        param.addParam(ParamConstants.PARAM_BASIC_OUTPUT_PATH, tmpOutputPath);
        param.addParam(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, DEFAULT_SIGN_ALG);

        String[] params = param.toArray();
        TestCodeSignServer server = new TestCodeSignServer();
        Assert.assertTrue("sign code failed", CodeSignTool.signCode(server, params));
        CodeSignVerify codeSignVerify = new CodeSignVerify();
        Assert.assertTrue("verify code failed", codeSignVerify.verifyCode(
            unsignedHap.getPath(), spliceFilePath(tmpOutputPath, unsignedHap.getName())));
    }

    private static String spliceFilePath(String outputDir, String hapName) {
        String outputPath = outputDir;
        if (!outputPath.endsWith(File.separator)) {
            outputPath += File.separator;
        }
        return new String(outputPath + hapName + SIG_SUFFIX);
    }

    private void testSignCodeWithTree() throws Exception {
        File unsignedHap = File.createTempFile(TMP_UNSIGNED_FILE_PREFIX, TMP_HAP_FILE_SUFFIX, TMP_DIR);
        tmpSources.add(new CleanableFile(unsignedHap));

        fillHapFile(unsignedHap);

        Params param = new Params();
        param.addParam(ParamConstants.PARAM_BASIC_INPUT_FILE, unsignedHap.getPath());
        param.addParam(ParamConstants.PARAM_BASIC_OUTPUT_PATH, tmpOutputPath);
        param.addParam(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, DEFAULT_SIGN_ALG);
        param.addParam(ParamConstants.PARAM_OUTPUT_MEKLE_TREE, OUTPUT_MERKLE_TREE);

        String[] params = param.toArray();
        TestCodeSignServer server = new TestCodeSignServer();
        Assert.assertTrue("sign code failed", CodeSignTool.signCode(server, params));
        CodeSignVerify codeSignVerify = new CodeSignVerify();
        Assert.assertTrue("verify code failed", codeSignVerify.verifyCode(
            unsignedHap.getPath(), spliceFilePath(tmpOutputPath, unsignedHap.getName())));
    }

    /**
     * Test sign code with option `CompressiveNativeLibs`
     *
     * @throws Exception an error.
     */
    @Test
    public void testSignHapWithLibOptions() throws Exception {
        for (String module : MODULE_TYPES) {
            for (String option : COMPRESS_NATIVE_LIB_OPTIONS) {
                String hapPath = TEST_TARGET_HAPS_BASE + SEPARATOR + module + SEPARATOR + option + HAP_SUFFIX;
                testSignCode(new File(hapPath), false);
                String outFile = tmpOutputPath + SEPARATOR + option + HAP_SUFFIX + SIG_SUFFIX;
                CheckNativeLibSignature check = new CheckNativeLibSignature(outFile);
                Assert.assertEquals("compress libs check failed",
                        check.checkLibDirInSignature(), OPTIONS_AND_LIB_SIGNATURE_MAP.get(option));
            }
        }
    }

    /**
     * Test Method: getVersion()
     *
     * @throws Exception on error.
     */
    @Test
    public void testGetVersion() throws Exception {
        Assert.assertNotNull(CodeSignTool.getVersion());
    }

    /**
     * Test unsupported sign algorithm
     *
     * @throws Exception on error.
     */
    @Test
    public void testUnSupportedSignAlgorithm() throws Exception {
        File unsignedHap = File.createTempFile(TMP_UNSIGNED_FILE_PREFIX, TMP_HAP_FILE_SUFFIX, TMP_DIR);
        tmpSources.add(new CleanableFile(unsignedHap));
        fillHapFile(unsignedHap);
        Params param = new Params();
        param.addParam(ParamConstants.PARAM_BASIC_INPUT_FILE, unsignedHap.getPath());
        param.addParam(ParamConstants.PARAM_BASIC_OUTPUT_PATH, tmpOutputPath);
        param.addParam(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, ParamConstants.SIG_ALGORITHM_SHA256_RSA);
        String[] params = param.toArray();
        TestCodeSignServer server = new TestCodeSignServer();
        Assert.assertFalse("sign using unsupported algorithm", CodeSignTool.signCode(server, params));
    }

    private byte[] generateChunkBytes() {
        Random random = new Random();
        int size = Math.max(MIN_DATA_CHUNK_SIZE, random.nextInt(MAX_DATA_CHUNK_SIZE + 1));
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    private String generateEntryName() {
        return new BigInteger(Long.SIZE, new Random()) + SO_SUFFIX;
    }

    private void fillHapFile(File file) throws IOException {
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(file))) {
            Random random = new Random();
            int entryCount = Math.max(MIN_ENTRY_COUNT, random.nextInt(MAX_ENTRY_COUNT + 1));
            for (int i = 0; i < entryCount; i++) {
                ZipEntry zipEntry = new ZipEntry(generateEntryName());
                out.putNextEntry(zipEntry);
                out.write(generateChunkBytes());
            }
        }
    }

    private interface Cleanable {
        /**
         * Clean template resources.
         */
        void clean();
    }

    private static class CheckNativeLibSignature {

        private static final String LIB_DIR_NAME = "libs";
        private static final String SO_SIG_SUFFIX = SO_SUFFIX + SINGLE_SIG_SUFFIX;

        private final File inputFile;

        public CheckNativeLibSignature(String filePath) {
            inputFile = new File(filePath);

        }

        /**
         * Check whether the signature file contains signature of native libs
         *
         * @return true if the file contains signature of native libs
         */
        public boolean checkLibDirInSignature() {
            try (JarFile inputJar = new JarFile(inputFile, false)) {
                for (Enumeration<JarEntry> e = inputJar.entries(); e.hasMoreElements();) {
                    JarEntry entry = e.nextElement();
                    if (entry.getName().startsWith(LIB_DIR_NAME) && entry.getName().endsWith(SO_SIG_SUFFIX)) {
                        return true;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return false;
        }
    }

    private static class MultiSignCodeTask implements Callable<Boolean> {
        private final File inputFile;
        private final String outputPath;
        private final CountDownLatch countDownLatch;

        /**
         * MultiSignCodeTask constructor.
         *
         * @param inHap          input hap file
         * @param outPath        signed output file path
         * @param countDownLatch count down latch on multi-thread
         */
        public MultiSignCodeTask(File inHap, String outPath, CountDownLatch countDownLatch) {
            this.inputFile = inHap;
            this.outputPath = outPath;
            this.countDownLatch = countDownLatch;
        }

        @Override
        public Boolean call() {
            try {
                Params params = new Params();
                TestCodeSignServer server = new TestCodeSignServer();
                params.addParam(ParamConstants.PARAM_BASIC_INPUT_FILE, inputFile.getPath());
                params.addParam(ParamConstants.PARAM_BASIC_OUTPUT_PATH, outputPath);
                params.addParam(ParamConstants.PARAM_BASIC_SIGANTURE_ALG, DEFAULT_SIGN_ALG);
                CodeSignVerify codeSignVerify = new CodeSignVerify();
                return (CodeSignTool.signCode(server, params.toArray()) &
                    codeSignVerify.verifyCode(inputFile.getPath(), spliceFilePath(outputPath, inputFile.getName())));
            } finally {
                countDownLatch.countDown();
            }
        }
    }

    private static class Params {
        private final Set<Param> params = new HashSet<>();

        /**
         * Add param.
         *
         * @param name  param name
         * @param value param value
         */
        public void addParam(String name, String value) {
            params.add(new Param(name, value));
        }

        /**
         * Parse to String[] params.
         *
         * @return String[] params
         */
        public String[] toArray() {
            List<String> paramList = new ArrayList<>(params.size());
            for (Param param : params) {
                paramList.add(param.getKey());
                paramList.add(param.getValue());
            }
            return paramList.toArray(new String[0]);
        }
    }

    private static class Param {
        private static final String DEFAULT_PREFIX = "-";

        private final String name;
        private final String value;
        private final String prefix;

        public Param(String name, String value) {
            this(name, value, DEFAULT_PREFIX);
        }

        public Param(String name, String value, String prefix) {
            this.name = name;
            this.value = value;
            this.prefix = prefix;
        }

        /**
         * Get parameter key.
         *
         * @return parameter key
         */
        public String getKey() {
            return prefix + name;
        }

        public String getValue() {
            return value;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (other == null || getClass() != other.getClass()) {
                return false;
            }
            if (other instanceof Param) {
                Param param = (Param) other;
                return Objects.equals(name, param.name);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(name);
        }
    }

    private static class CleanableFile implements Cleanable {
        private final File file;

        public CleanableFile(File file) {
            this.file = file;
        }

        @Override
        public void clean() {
            if (file != null && file.exists() && file.isFile()) {
                try {
                    Files.delete(file.toPath());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
