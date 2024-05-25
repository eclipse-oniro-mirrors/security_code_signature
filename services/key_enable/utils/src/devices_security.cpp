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

#include "devices_security.h"

#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <securec.h>

#include "log.h"
#include "parameter.h"

constexpr int32_t VALUE_MAX_LEN = 64;
constexpr int32_t CMDLINE_MAX_BUF_LEN = 4096;
static const std::string OEM_MODE = "const.boot.oemmode";
static const std::string OEM_MODE_RD = "rd";
static const std::string EFUSE_STATE_FILE = "/proc/cmdline";

using namespace OHOS::Security::CodeSign;

int32_t GetEfuseStatus()
{
    int32_t fd = open(EFUSE_STATE_FILE.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR(LABEL, "open %{public}s failed, %{public}s", EFUSE_STATE_FILE.c_str(), strerror(errno));
        return DEVICE_MODE_ERROR;
    }

    char *buf = static_cast<char *>(malloc(CMDLINE_MAX_BUF_LEN));
    if (buf == nullptr) {
        LOG_ERROR(LABEL, "alloc read buffer failed");
        (void) close(fd);
        return DEVICE_MODE_ERROR;
    }
    (void)memset_s(buf, CMDLINE_MAX_BUF_LEN, 0, CMDLINE_MAX_BUF_LEN);

    int32_t deviceMode = DEVICE_MODE_ERROR;
    ssize_t ret = read(fd, buf, CMDLINE_MAX_BUF_LEN - 1);
    (void) close(fd);
    if (ret < 0) {
        LOG_ERROR(LABEL, "read %{public}s failed, %{public}s", EFUSE_STATE_FILE.c_str(), strerror(errno));
        free(buf);
        buf = nullptr;
        return deviceMode;
    }

    if (strstr(buf, "efuse_status=0")) {
        LOG_DEBUG(LABEL, "device is fused, need to check device id");
        deviceMode = DEVICE_MODE_USER;
    } else if (strstr(buf, "efuse_status=1")) {
        LOG_DEBUG(LABEL, "device is not fused, skip device id check");
        deviceMode = DEVICE_MODE_RD;
    } else {
        LOG_ERROR(LABEL, "failed to obtain the device efuse status");
    }

    free(buf);
    buf = nullptr;
    return deviceMode;
}

int32_t GetDeviceMode()
{
    LOG_DEBUG(LABEL, "start to check the OEM mode of the device");

    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(OEM_MODE.c_str(), nullptr, value, sizeof(value));
    if ((ret >= 0) && (strncmp(value, OEM_MODE_RD.c_str(), sizeof(value)) == 0)) {
        LOG_DEBUG(LABEL, "oem mode is rd, skip device id check");
        return DEVICE_MODE_RD;
    }

    return GetEfuseStatus();
}
bool IsRdDevice()
{
    if (GetDeviceMode() != DEVICE_MODE_RD) {
        return false;
    }
    return true;
}