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

#include "security_guard_report.h"

#include "cJSON.h"
#include "event_info.h"
#include "log.h"
#include "sg_collect_client.h"
#include <memory>
#include <unistd.h>

namespace OHOS {
namespace Security {
namespace CodeSign {
namespace {
constexpr int64_t LOCAL_CODE_SIGN_EVENT_ID = 0x0120010A5;
constexpr const char *LOCAL_CODE_SIGN_EVENT_VERSION = "1.0";
constexpr size_t FD_PATH_MAX_LEN = 4096;
} // namespace

std::string SecurityGuardReport::GetPathFromFd(int32_t fd)
{
    std::string fdPath = "/proc/self/fd/" + std::to_string(fd);
    char buf[FD_PATH_MAX_LEN] = {0};
    ssize_t len = readlink(fdPath.c_str(), buf, sizeof(buf) - 1);
    if (len <= 0) {
        LOG_ERROR("Get path from fd=%{public}d failed", fd);
        return "";
    }
    return std::string(buf, static_cast<size_t>(len));
}

void SecurityGuardReport::ReportLocalCodeSignSecurityInfo(uint32_t callerUid, int32_t callerPid, int32_t fd,
    const std::string &ownerId, int32_t signResult)
{
    std::string filePath = GetPathFromFd(fd);
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        LOG_ERROR("cJSON_CreateObject failed");
        return;
    }
    cJSON_AddNumberToObject(root, "callerUid", static_cast<double>(callerUid));
    cJSON_AddNumberToObject(root, "callerPid", static_cast<double>(callerPid));
    cJSON_AddStringToObject(root, "filePath", filePath.c_str());
    cJSON_AddStringToObject(root, "ownerId", ownerId.c_str());
    cJSON_AddNumberToObject(root, "signResult", static_cast<double>(signResult));
    char *jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        LOG_ERROR("cJSON_PrintUnformatted failed");
        return;
    }
    std::string content(jsonStr);
    cJSON_free(jsonStr);
    auto eventInfo = std::make_shared<OHOS::Security::SecurityGuard::EventInfo>(
        LOCAL_CODE_SIGN_EVENT_ID, LOCAL_CODE_SIGN_EVENT_VERSION, content);
    int32_t ret = OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfoAsync(eventInfo);
    if (ret != 0) {
        LOG_WARN("ReportSecurityInfoAsync failed, ret=%{public}d", ret);
    }
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
