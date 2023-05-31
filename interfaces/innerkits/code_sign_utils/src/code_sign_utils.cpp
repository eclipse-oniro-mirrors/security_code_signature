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

#include "code_sign_utils.h"

#include <asm/unistd.h>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <sys/types.h>
#include <unistd.h>

#include "cs_hisysevent.h"
#include "cs_hitrace.h"
#include "constants.h"
#include "directory_ex.h"
#include "extractor.h"
#include "file_helper.h"
#include "log.h"
#include "stat_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t DEFAULT_HASH_ALGORITHEM = FS_VERITY_HASH_ALG_SHA256;
constexpr uint32_t HASH_PAGE_SIZE = 4096;

int32_t CodeSignUtils::EnforceCodeSignForApp(const EntryMap &entryPath,
    const std::string &signatureFile)
{
    // no files to enable, return directly
    if (entryPath.empty()) {
        return CS_SUCCESS;
    }

    if (!CheckFilePathValid(signatureFile, Constants::ENABLE_SIGNATURE_FILE_BASE_PATH)) {
        LOG_ERROR(LABEL, "Signature file is invalid.");
        return CS_ERR_FILE_PATH;
    }

    // check whether fs-verity is supported by kernel
    auto iter = entryPath.begin();
    int32_t ret = CodeSignUtils::IsSupportFsVerity(iter->second);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    std::unique_ptr<AbilityBase::Extractor> extractor = std::make_unique<AbilityBase::Extractor>(signatureFile);
    std::vector<std::string> signatureFileList;
    if (!extractor->Init()) {
        LOG_ERROR(LABEL, "Init extractor failed.");
        return CS_ERR_EXTRACT_FILES;
    }
    // Get signature file entry name
    extractor->GetSpecifiedTypeFiles(signatureFileList, Constants::FSV_SIG_SUFFIX);

    for (const auto &pathPair: entryPath) {
        const std::string &entryName = pathPair.first;
        const std::string &targetFile = pathPair.second;
        LOG_DEBUG(LABEL, "Enable entry %{public}s, path = %{public}s", entryName.c_str(), targetFile.c_str());
        if (!CheckFilePathValid(targetFile, Constants::ENABLE_APP_BASE_PATH)) {
            LOG_ERROR(LABEL, "App file is invalid.");
            return CS_ERR_FILE_PATH;
        }
        const std::string &signatureEntry = entryName + Constants::FSV_SIG_SUFFIX;
        if (std::find(signatureFileList.begin(), signatureFileList.end(), signatureEntry) == signatureFileList.end()) {
            LOG_ERROR(LABEL, "Fail to find signature for %{public}s", entryName.c_str());
            return CS_ERR_NO_SIGNATURE;
        }
        std::unique_ptr<uint8_t[]> signatureBuffer = nullptr;
        size_t signatureSize;
        if (!extractor->ExtractToBufByName(signatureEntry, signatureBuffer, signatureSize)) {
            LOG_ERROR(LABEL, "Extract signture failed.");
            return CS_ERR_EXTRACT_FILES;
        }
        ret = EnforceCodeSignForFile(targetFile, signatureBuffer.get(), signatureSize);
        if (ret != CS_SUCCESS) {
            return ret;
        }
    }
    return CS_SUCCESS;
}

int32_t CodeSignUtils::IsSupportFsVerity(const std::string &path)
{
    struct statx stat = {};
    if (Statx(AT_FDCWD, path.c_str(), 0, STATX_ALL, &stat) != 0) {
        LOG_ERROR(LABEL, "Get attributes failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        return CS_ERR_FILE_INVALID;
    }
    if (stat.stx_attributes_mask & STATX_ATTR_VERITY) {
        return CS_SUCCESS;
    }
    LOG_INFO(LABEL, "Fs-verity is not supported.");
    return CS_ERR_FSVREITY_NOT_SUPPORTED;
}

int32_t CodeSignUtils::IsFsVerityEnabled(int fd)
{
    unsigned int flags;
    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    if (ret < 0) {
        LOG_ERROR(LABEL, "Get verity flags by ioctl failed. errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        return CS_ERR_FILE_INVALID;
    }
    if (flags & FS_VERITY_FL) {
        return CS_SUCCESS;
    }
    return CS_ERR_FSVERITY_NOT_ENABLED;
}

int32_t CodeSignUtils::EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature)
{
    return EnforceCodeSignForFile(path, signature.GetBuffer(), signature.GetSize());
}

int32_t CodeSignUtils::EnforceCodeSignForFile(const std::string &path, const uint8_t *signature,
    const size_t size)
{
    if ((signature == nullptr) || (size == 0)) {
        return CS_ERR_NO_SIGNATURE;
    }
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        LOG_INFO(LABEL, "Get real path failed, path = %{public}s", path.c_str());
        return CS_ERR_FILE_PATH;
    }
    int fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR(LABEL, "Open file failed, path = %{public}s, errno = <%{public}d, %{public}s>",
            realPath.c_str(), errno, strerror(errno));
        return CS_ERR_FILE_OPEN;
    }
    int32_t ret = IsFsVerityEnabled(fd);
    if (ret == CS_SUCCESS) {
        close(fd);
        LOG_INFO(LABEL, "Fs-verity has been enabled.");
        return CS_SUCCESS;
    } else if (ret == CS_ERR_FILE_INVALID) {
        close(fd);
        return CS_ERR_FILE_INVALID;
    }
    struct fsverity_enable_arg arg = {};
    arg.version = 1;    // version of fs-verity, must be 1
    arg.hash_algorithm = DEFAULT_HASH_ALGORITHEM;
    arg.block_size = HASH_PAGE_SIZE;
    arg.salt_ptr = 0;
    arg.salt_size = 0;
    arg.sig_size = size;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signature);
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, CODE_SIGN_ENABLE_START);
    int error = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
    if (error < 0) {
        close(fd);
        LOG_ERROR(LABEL, "Enable fs-verity failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        ReportEnableError(path, errno);
        return CS_ERR_ENABLE;
    }
    close(fd);
    return CS_SUCCESS;
}
}
}
}
