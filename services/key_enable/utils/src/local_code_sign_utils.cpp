/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "local_code_sign_utils.h"

#include "securec.h"

#include "byte_buffer.h"
#include "local_code_sign_kit.h"

using namespace OHOS::Security::CodeSign;

int32_t InitLocalCertificate(uint8_t *certData, uint32_t *certSize)
{
    ByteBuffer cert;
    int32_t ret = LocalCodeSignKit::InitLocalCertificate(cert);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    if (memcpy_s(certData, *certSize, cert.GetBuffer(), cert.GetSize()) != EOK) {
        return CS_ERR_MEMORY;
    }
    *certSize = cert.GetSize();
    return CS_SUCCESS;
}