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

#include <cstdlib>
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "byte_buffer.h"
#include "local_code_sign_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {

static uint64_t NativeTokenSet(const char* caller)
{
    uint64_t tokenId = GetSelfTokenID();
    uint64_t mockTokenID = AccessTokenKit::GetNativeTokenId(caller);
    SetSelfTokenID(mockTokenID);
    return tokenId;
}

static void NativeTokenReset(uint64_t tokenId)
{
    SetSelfTokenID(tokenId);
}

class LocalCodeSignTest : public testing::Test {
public:
    LocalCodeSignTest() {};
    virtual ~LocalCodeSignTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: LocalCodeSignTest_0001
 * @tc.desc: init local certificate successfully
 * @tc.type: Func
 * @tc.require: AR000HS08H
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0001, TestSize.Level0)
{
    ByteBuffer cert;
    uint64_t selfTokenId = NativeTokenSet("key_enable");
    int ret = LocalCodeSignKit::InitLocalCertificate(cert);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: LocalCodeSignTest_0002
 * @tc.desc: init local certificate failed with invalid caller
 * @tc.type: Func
 * @tc.require: AR000HS08H
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0002, TestSize.Level0)
{
    ByteBuffer cert;
    int ret = LocalCodeSignKit::InitLocalCertificate(cert);
    EXPECT_EQ(ret, CS_ERR_NO_PERMISSION);
}
} //namespace CodeSign
} //namespace Security
} //namespace OHOS
