/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>

#include "security_guard_report.h"

using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string TEST_FILE_PATH = "/data/test/tmp/demo.an";

class SecurityGuardReportTest : public testing::Test {
public:
    SecurityGuardReportTest() {};
    virtual ~SecurityGuardReportTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: SecurityGuardReportTest_0001
 * @tc.desc: ReportLocalCodeSignSecurityInfo with valid fd and normal ownerId
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0001, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, "AppName123", 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0003
 * @tc.desc: ReportLocalCodeSignSecurityInfo with ownerId containing double quotes (JSON injection payload)
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0003, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string ownerId = "test\"injected\":true}";
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, ownerId, 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0004
 * @tc.desc: ReportLocalCodeSignSecurityInfo with ownerId containing backslash
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0004, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string ownerId = "test\\backslash\\path";
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, ownerId, 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0005
 * @tc.desc: ReportLocalCodeSignSecurityInfo with empty ownerId
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0005, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, "", 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0006
 * @tc.desc: ReportLocalCodeSignSecurityInfo with negative signResult
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0006, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, "AppName123", -517);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0007
 * @tc.desc: ReportLocalCodeSignSecurityInfo with ownerId at max length (32 bytes)
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0007, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string ownerId(32, 'a');
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, ownerId, 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0008
 * @tc.desc: ReportLocalCodeSignSecurityInfo with ownerId containing full JSON object (injection attempt)
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0008, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string ownerId = "{\"evil\":\"value\",\"extra\":123}";
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, ownerId, -1);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0009
 * @tc.desc: ReportLocalCodeSignSecurityInfo with ownerId containing control characters
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0009, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string ownerId = "test\ttab\nnewline\rcr";
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, ownerId, 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0010
 * @tc.desc: ReportLocalCodeSignSecurityInfo with closed fd
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0010, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    close(fd);
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, "AppName123", 0);
    SUCCEED();
}

/**
 * @tc.name: SecurityGuardReportTest_0011
 * @tc.desc: ReportLocalCodeSignSecurityInfo with large callerUid and callerPid values
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0011, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    SecurityGuardReport::ReportLocalCodeSignSecurityInfo(4294967295, 2147483647, fd, "AppName123", 0);
    SUCCEED();
    close(fd);
}

/**
 * @tc.name: SecurityGuardReportTest_0012
 * @tc.desc: ReportLocalCodeSignSecurityInfo called multiple times consecutively
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SecurityGuardReportTest, SecurityGuardReportTest_0012, TestSize.Level0)
{
    int fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    for (int i = 0; i < 10; i++) {
        SecurityGuardReport::ReportLocalCodeSignSecurityInfo(1000, 100, fd, "AppName123", i);
    }
    SUCCEED();
    close(fd);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
