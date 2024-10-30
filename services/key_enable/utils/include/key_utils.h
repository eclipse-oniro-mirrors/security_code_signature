/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef CODE_SIGN_KEY_UTILS_H
#define CODE_SIGN_KEY_UTILS_H

#ifndef LOG_RUST
#define LOG_RUST
#endif

#include <sys/types.h>

typedef int32_t KeySerial;

#ifdef __cplusplus
extern "C" {
#endif

KeySerial AddKey(
    const char *type,
    const char *description,
    const unsigned char *payload,
    size_t pLen,
    KeySerial ringId);

KeySerial KeyctlRestrictKeyring(
    KeySerial ringId,
    const char *type,
    const char *restriction);

bool IsRdDevice();
int32_t CheckEfuseStatus(char *buf, ssize_t bunLen);
#ifdef __cplusplus
}
#endif

#endif