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

#ifndef CODE_SIGN_ACCESS_TOKEN_SETTER_H
#define CODE_SIGN_ACCESS_TOKEN_SETTER_H

#include <cstdint>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace OHOS::Security::AccessToken;

inline uint64_t NativeTokenSet(const char *caller)
{
    uint64_t tokenId = GetSelfTokenID();
    uint64_t mockTokenId = AccessTokenKit::GetNativeTokenId(caller);
    SetSelfTokenID(mockTokenId);
    return tokenId;
}

inline void NativeTokenReset(uint64_t tokenId)
{
    SetSelfTokenID(tokenId);
}
}
}
}
#endif
