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

#ifndef CODE_SIGN_HUKS_ATTEST_HELPER_H
#define CODE_SIGN_HUKS_ATTEST_HELPER_H

#include <openssl/x509.h>
#include "byte_buffer.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
bool GetVerifiedCert(const ByteBuffer &buffer, const ByteBuffer &challenge, ByteBuffer &cert);
bool VerifyCertAndExtension(X509 *signCert, X509 *issuerCert, const ByteBuffer &challenge);
}
}
}
#endif