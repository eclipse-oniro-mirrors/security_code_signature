/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <string>

#include "devices_security.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {

class KeyEnableUtilsTest : public testing::Test {
public:
    KeyEnableUtilsTest() {};
    virtual ~KeyEnableUtilsTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: KeyEnableUtilsTest_0001
 * @tc.desc: Obtaining cmdline node data from aarch64 device
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0001, TestSize.Level0)
{
    int32_t efuseStatus = GetEfuseStatus();
    EXPECT_NE(efuseStatus, DEVICE_MODE_ERROR);
}

/**
 * @tc.name: KeyEnableUtilsTest_0001
 * @tc.desc: Obtaining device mode from aarch64 device
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0002, TestSize.Level0)
{
    int32_t deviceMode = GetDeviceMode();
    EXPECT_NE(deviceMode, DEVICE_MODE_ERROR);
}

} // namespace CodeSign
} // namespace Security
} // namespace OHOS
