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

#ifndef CODE_SIGN_LOG_H
#define CODE_SIGN_LOG_H

#ifdef HOST_TOOL
#include "tool_log.h"
#else
#include "hilog/log.h"
#endif

namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr unsigned int SECURITY_DOMAIN = 0xD002F00;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN, "CODE_SIGN"};

#define LOG_DEBUG(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Debug(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_INFO(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Info(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_WARN(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Warn(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_ERROR(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Error(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_FATAL(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Fatal(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
}
}
}
#endif