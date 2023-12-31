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

#include <gtest/gtest.h>

#include "code_sign_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace testing::ext;
using namespace std;

static const std::string TMP_BASE_PATH = "/data/service/el1/public/bms/bundle_manager_service/tmp";
static const std::string APP_BASE_PATH = "/data/app/el1/bundle/public/tmp";

static const EntryMap g_hapWithoutLibRetSuc = {
    {"Hap", APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap"},
};
static const std::string g_sigWithoutLibRetSucPath =
    TMP_BASE_PATH + "/demo_without_lib/demo_without_lib.sig";

static EntryMap g_hapWithMultiLibRetSuc = {
    {"Hap",
        APP_BASE_PATH + "/demo_with_multi_lib/demo_with_multi_lib.hap"},
    {"libs/arm64-v8a/libc++_shared.so",
        APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libc++_shared.so"},
    {"libs/arm64-v8a/libentry.so",
        APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so"}
};
static const std::string g_sigWithMultiLibRetSucPath =
    TMP_BASE_PATH + "/demo_with_multi_lib/demo_with_multi_lib.sig";

// wrong hap and wrong lib
static EntryMap g_wrongHapWithMultiLibRetFail = {
    {"Hap",
     APP_BASE_PATH + "/demo_with_multi_lib_error/demo_with_multi_lib.hap"},
    {"libs/arm64-v8a/libc++_shared.so",
     APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libc++_shared.so"},
    {"libs/arm64-v8a/libentry.so",
     APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libentry.so"}};

// examples of Enforce code signature for app
static const std::vector<std::string> g_HapWithoutLibSigPkcs7ErrorPath = {
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_001.sig", // Ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_002.sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_003.sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_004.sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_005.sig", // Wrong signature
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_006.sig", // Expired signature
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_007.sig", // Cert chain validate fail
};

static const std::vector<std::string> g_HapWithMultiLibSigPkcs7ErrorPath = {
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_001.sig", // Ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_002.sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_003.sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_004.sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_005.sig", // Wrong signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_006.sig", // Expired signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_007.sig", // Cert chain validate fail
};

// examples of Enforce code signature for file
static const std::string g_fileEnableSuc = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so";
static const std::string g_filesigEnablePath =
    TMP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so.fsv-sig";

// wrong format file
static const std::string g_wrongFileEnableFail =
    APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libentry.so";

static const std::vector<std::string> g_fileSigEnableFailPath = {
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_01.so.fsv-sig", // ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_02.so.fsv-sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_03.so.fsv-sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_04.so.fsv-sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_05.so.fsv-sig", // Wrong signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_06.so.fsv-sig", // Expired signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_07.so.fsv-sig", // Cert chain validate fail
};

// examples of can't find the signature file
static const EntryMap g_hapSigNotExist = {
    {"sigNotExist", APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap"},
};

class CodeSignUtilsTest : public testing::Test {
public:
    CodeSignUtilsTest() {};
    virtual ~CodeSignUtilsTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

static bool ReadSignatureFromFile(const std::string &path, ByteBuffer &data)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        fclose(file);
        return false;
    }

    size_t fileSize = ftell(file);
    rewind(file);
    if (!data.Resize(fileSize)) {
        fclose(file);
        return false;
    }
    size_t ret = fread(data.GetBuffer(), 1, fileSize, file);
    (void)fclose(file);
    return ret == fileSize;
}

// excute the exceptional examples first, because of it's always successful
// once the same file signature verified successfully

/**
 * @tc.name: CodeSignUtilsTest_0001
 * @tc.desc: enable code signature for app failed, reason = zip file wrong foramt
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0001, TestSize.Level0)
{
    std::string sigPath = TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_01.so.fsv-sig";
    int ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, sigPath);
    EXPECT_EQ(ret, CS_ERR_EXTRACT_FILES);
}

/**
 * @tc.name: CodeSignUtilsTest_0002
 * @tc.desc: enable code signature for app failed, reason = no signature in the signatrue file
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0002, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(g_hapSigNotExist, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: CodeSignUtilsTest_0003
 * @tc.desc: enable code signature for app failed, reason = invalied signature path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0003, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(
        g_hapWithoutLibRetSuc, g_sigWithoutLibRetSucPath + "invalid");
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}


/**
 * @tc.name: CodeSignUtilsTest_0004
 * @tc.desc: enable code signature for app failed, reason = invalied hap path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0004, TestSize.Level0)
{
    EntryMap invalid;
    invalid["Hap"] = "InvalidPath";
    int ret = CodeSignUtils::EnforceCodeSignForApp(invalid, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_FILE_INVALID);
}

/**
 * @tc.name: CodeSignUtilsTest_0005
 * @tc.desc: enable code signature for app failed, reason = wrong format hap
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0005, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(
        g_wrongHapWithMultiLibRetFail, g_sigWithMultiLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: CodeSignUtilsTest_0006
 * @tc.desc: enable code signature for app failed, reason = enable failed
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0006, TestSize.Level0)
{
    size_t num = g_HapWithoutLibSigPkcs7ErrorPath.size();
    int ret;
    // wrong hap signature
    for (size_t i = 0; i < num; i++) {
        ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, g_HapWithoutLibSigPkcs7ErrorPath[i]);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }

    // wrong so signature
    num = g_HapWithMultiLibSigPkcs7ErrorPath.size();
    for (size_t i = 0; i < num; i++) {
        ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithMultiLibRetSuc, g_HapWithMultiLibSigPkcs7ErrorPath[i]);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0007
 * @tc.desc: enable code signature for file, reason = wrong foramt pkcs7
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0007, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);
    int ret = CodeSignUtils::EnforceCodeSignForFile(g_wrongFileEnableFail, buffer);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: CodeSignUtilsTest_0008
 * @tc.desc: enable code signature for file, reason = enable failed
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0008, TestSize.Level0)
{
    size_t num = g_fileSigEnableFailPath.size();
    int ret;
    for (size_t i = 0; i < num; i++) {
        ByteBuffer buffer;
        bool flag = ReadSignatureFromFile(g_fileSigEnableFailPath[i], buffer);
        EXPECT_EQ(flag, true);
        ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0009
 * @tc.desc: enable code signature for file failed, reason = invalid path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0009, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);
    int ret = CodeSignUtils::EnforceCodeSignForFile("invalidPath", buffer);
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}

/**
 * @tc.name: CodeSignUtilsTest_0010
 * @tc.desc: enable code signature for file failed, reason = no signature
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0010, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);

    int ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, NULL, buffer.GetSize());
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);

    ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer.GetBuffer(), 0);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: CodeSignUtilsTest_0011
 * @tc.desc: enable code signature for file successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0011, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);

    int ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0012
 * @tc.desc: enable code signature for app successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0012, TestSize.Level0)
{
    int ret;
    ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_SUCCESS);

    ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithMultiLibRetSuc, g_sigWithMultiLibRetSucPath);
    EXPECT_EQ(ret, CS_SUCCESS);
}
}  // namespace CodeSign
}  // namespace Security
}  // namespace OHOS