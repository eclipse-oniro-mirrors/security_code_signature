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

#ifndef OHOS_SECURITY_CODE_SIGN_UTILS_H
#define OHOS_SECURITY_CODE_SIGN_UTILS_H

#include <cstdint>
#include <mutex>
#include <string>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unordered_map>
#include <linux/fsverity.h>
#include "byte_buffer.h"
#include "errcode.h"
#ifdef SUPPORT_BINARY_ENABLE
#include "cert_path.h"
#endif

namespace OHOS {
namespace Security {
namespace CodeSign {
using EntryMap = std::unordered_map<std::string, std::string>;

typedef enum {
    FILE_ALL, // Enable hap and so(new and historical records)
    FILE_SELF, // Only enable hap
    FILE_ENTRY_ONLY, // Only enable so(new and historical records)
    FILE_ENTRY_ADD, // Only record, not enable
    FILE_TYPE_MAX,
} FileType;

enum CodeSignInfoFlag {
    IS_UNCOMPRESSED_NATIVE_LIBS = 0x01 << 0,
};

class CodeSignUtils {
public:
    /**
     * @brief Enforce code signature for a hap
     * @param entryPath map from entryname in hap to real path on disk
     * @param signatureFile signature file path
     * @return err code, see err_code.h
     */
    static int32_t EnforceCodeSignForApp(const EntryMap &entryPath, const std::string &signatureFile);

    /**
     * @brief Enforce code signature for a hap with its native files.
     * Multiple instances should be created to enable code signing for a multi-hap app.
     * @param path hap real path on disk
     * @param entryPath map from entryname in hap to real path on disk
     * @param type signature file type
     * @param flag attributes of libs
     * @return err code, see err_code.h
     */
    int32_t EnforceCodeSignForApp(const std::string &path, const EntryMap &entryPathMap,
        FileType type, uint32_t flag = 0);

    /**
     * @brief Enforce code signature for a hap with owner ID
     * @param ownerId app-identifier of the signature
     * @param path hap real path on disk
     * @param entryPath map from entryname in hap to real path on disk
     * @param type signature file type
     * @param flag attributes of libs
     * @return err code, see err_code.h
     */
    int32_t EnforceCodeSignForAppWithOwnerId(const std::string &ownerId, const std::string &path,
        const EntryMap &entryPathMap, FileType type, uint32_t flag = 0);

    /**
     * @brief Enforce code signature for a hap with plugin ID
     * @param ownerId app-identifier of the signature
     * @param pluginId plugin-identifier of the signature
     * @param path hap real path on disk
     * @param entryPath map from entryname in hap to real path on disk
     * @param type signature file type
     * @param flag attributes of libs
     * @return err code, see err_code.h
     */
    int32_t EnforceCodeSignForAppWithPluginId(const std::string &ownerId, const std::string &pluginId,
        const std::string &path, const EntryMap &entryPathMap, FileType type, uint32_t flag = 0);

    /**
     * @brief Enforce code signature for file with signature
     * @param path file path
     * @param signature buffer carring signature of the target file
     * @param len length of signature data
     * @return err code, see err_code.h
     */
    static int32_t EnforceCodeSignForFile(const std::string &path, const uint8_t *signature, const uint32_t len);

    /**
     * @brief Enforce code signature for file with signature
     * @param path file path
     * @param signature bytebuffer carring signature of the target file
     * @return err code, see err_code.h
     */
    static int32_t EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature);
    /**
     * @brief Get owner ID from signature file
     * @param sigbuffer buffer of the signature file
     * @param ownerID string to abtain owner ID from the signature file
     * @return err code, see err_code.h
     */
    static int ParseOwnerIdFromSignature(const ByteBuffer &sigbuffer, std::string &ownerID);
    /**
     * @brief Enable key in profile content data and dump profile buffer
     * @param bundleName bundleName
     * @param profileBuffer profile bytebuffer carring signer info and signed cert info
     * @return err code, see err_code.h
     */
    static int32_t EnableKeyInProfile(const std::string &bundleName, const ByteBuffer &profileBuffer);
    /**
     * @brief Remove key in profile content data and remove profile
     * @param bundleName bundleName
     * @return err code, see err_code.h
     */
    static int32_t RemoveKeyInProfile(const std::string &bundleName);

#ifdef SUPPORT_BINARY_ENABLE
    /**
    * @brief Enable certificate path
    * @param info CertPathInfo structure containing path information
    * @return err code, see err_code.h
    */
    static int32_t EnableKey(const CertPathInfo &info);

    /**
    * @brief Remove certificate path
    * @param info CertPathInfo structure containing path information
    * @return err code, see err_code.h
    */
    static int32_t RemoveKey(const CertPathInfo &info);

    /**
     * @brief Enforce code signature for elf file
     * @param path file path
     * @return err code, see err_code.h
     */
    static int32_t EnforceCodeSignForFile(const std::string &path);
#endif

    /**
     * @brief Whether enabling code signing for app compiled by oh-sdk
     * @return return ture if support oh-sdk code sign
     */
    static bool IsSupportOHCodeSign();
    /**
     * @brief Check if code signing is permissive
     * @return return ture if in permissive mode
     */
    static bool InPermissiveMode();
    /**
     * @brief Check if the file path support FsVerity
     * @param path file path
     * @return err code, see err_code.h
     */
    static int32_t IsSupportFsVerity(const std::string &path);
private:
    static int32_t EnableCodeSignForFile(const std::string &path, const struct code_sign_enable_arg &arg);
    int32_t ProcessCodeSignBlock(const std::string &ownerId, const std::string &pluginId,
        const std::string &path, FileType type, uint32_t flag);
    int32_t HandleCodeSignBlockFailure(const std::string &realPath, int32_t ret);
private:
    EntryMap storedEntryMap_;
    std::mutex storedEntryMapLock_;
};
}
}
}
#endif
