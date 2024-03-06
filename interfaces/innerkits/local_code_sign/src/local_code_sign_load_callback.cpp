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

#include "local_code_sign_load_callback.h"

#include "errcode.h"
#include "iremote_proxy.h"
#include "local_code_sign_client.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
LocalCodeSignLoadCallback::LocalCodeSignLoadCallback()
{
}

void LocalCodeSignLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    LOG_INFO("load local code sign SA success, systemAbilityId:%{public}d, remoteObject result:%{public}s",
        systemAbilityId, (remoteObject != nullptr) ? "true" : "false");
    if (systemAbilityId != LOCAL_CODE_SIGN_SA_ID) {
        LOG_ERROR("start systemabilityId is not codesignSAId!");
        return;
    }
    if (remoteObject == nullptr) {
        LOG_ERROR("remoteObject is nullptr");
        return;
    }
    LocalCodeSignClient::GetInstance().FinishStartSA(remoteObject);
}

void LocalCodeSignLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    LOG_ERROR("load local code sign SA failed, systemAbilityId: %{public}d", systemAbilityId);
    LocalCodeSignClient::GetInstance().FailStartSA();
}
}
}
}