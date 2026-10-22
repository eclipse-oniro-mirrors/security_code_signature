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

#ifndef CODE_SIGN_SECURITY_GUARD_REPORT_H
#define CODE_SIGN_SECURITY_GUARD_REPORT_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Security {
namespace CodeSign {
class SecurityGuardReport {
public:
    static void ReportLocalCodeSignSecurityInfo(uint32_t callerUid, int32_t callerPid, int32_t fd,
        const std::string &ownerId, int32_t signResult);

private:
    static std::string GetPathFromFd(int32_t fd);
};
} // namespace CodeSign
} // namespace Security
} // namespace OHOS

#endif // CODE_SIGN_SECURITY_GUARD_REPORT_H
