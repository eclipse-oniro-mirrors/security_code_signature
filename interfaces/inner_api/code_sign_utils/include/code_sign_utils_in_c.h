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

#ifndef CODE_SIGN_UTILS_IN_C_H
#define CODE_SIGN_UTILS_IN_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum FileType {
    FILE_ALL, // Enable hap and so(new and historical records)
    FILE_SELF, // Only enable hap
    FILE_ENTRY_ONLY, // Only enable so(new and historical records)
    FILE_ENTRY_ADD, // Only record, not enable
    FILE_TYPE_MAX,
};

enum CodeSignInfoFlag {
    IS_UNCOMPRESSED_NATIVE_LIBS = 0x01 << 0,
    IS_ENTERPRISE_RESIGN = 0x01 << 1,
    IS_LOCAL_HSP_PLUGIN = 0x01 << 2,
    IS_SIDE_LOADING_APP = 0x01 << 3,
};

struct EntryMapEntry {
    char* key;
    char* value;
};

struct EntryMapEntryData {
    int count;
    struct EntryMapEntry *entries;
};

/**
 * @brief Enforce code signature for a hap with its native files.
 * Multiple instances should be created to enable code signing for a multi-hap app.
 * The C language supports neither default arguments nor overloading, so this
 * entry is a compatibility wrapper of EnforceCodeSignForAppWithFlag with flag = 0.
 * @param hapPath hap real path on disk
 * @param entryMapEntryData map from entryname in hap to real path on disk
 * @param type signature file type
 * @return err code, see errcode.h
 */
int EnforceCodeSignForApp(const char *hapPath, const struct EntryMapEntryData *entryMapEntryData, enum FileType type);

/**
 * @brief Enforce code signature for a hap with its native files and libs attributes.
 * @param hapPath hap real path on disk
 * @param entryMapEntryData map from entryname in hap to real path on disk
 * @param type signature file type
 * @param flag attributes of libs, see CodeSignInfoFlag
 * @return err code, see errcode.h
 */
int EnforceCodeSignForAppWithFlag(const char *hapPath, const struct EntryMapEntryData *entryMapEntryData,
    enum FileType type, uint32_t flag);

#ifdef __cplusplus
}
#endif

#endif // CODE_SIGN_UTILS_IN_C_H