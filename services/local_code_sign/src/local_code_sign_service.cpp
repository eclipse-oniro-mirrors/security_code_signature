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

#include "local_code_sign_service.h"

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "local_sign_key.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
const std::string TASK_ID = "unload";
constexpr int32_t DELAY_TIME = 180000;

REGISTER_SYSTEM_ABILITY_BY_ID(LocalCodeSignService, LOCAL_CODE_SIGN_SA_ID, true);

LocalCodeSignService::LocalCodeSignService(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
}

void LocalCodeSignService::OnStart()
{
    if (!Init()) {
        LOG_ERROR(LABEL, "Init LocalCodeSignService failed.");
        return;
    }
    DelayUnloadTask();
    Publish(this);
}

bool LocalCodeSignService::Init()
{
    auto runner = AppExecFwk::EventRunner::Create(TASK_ID);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    if (unloadHandler_ == nullptr) {
        return false;
    }
    return true;
}

void LocalCodeSignService::DelayUnloadTask()
{
    auto task = [this]() {
        sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            LOG_ERROR(LABEL, "Get system ability mgr failed.");
            return;
        }
        int ret = samgr->UnloadSystemAbility(LOCAL_CODE_SIGN_SA_ID);
        if (ret != ERR_OK) {
            LOG_ERROR(LABEL, "Remove system ability failed.");
            return;
        }
    };
    unloadHandler_->RemoveTask(TASK_ID);
    unloadHandler_->PostTask(task, TASK_ID, DELAY_TIME);
}

void LocalCodeSignService::OnStop()
{
}

int32_t LocalCodeSignService::InitLocalCertificate(ByteBuffer &cert)
{
    LocalSignKey &key = LocalSignKey::GetInstance();
    if (!key.InitKey()) {
        LOG_ERROR(LABEL, "Init key failed.");
        return CS_ERR_HUKS_INIT_KEY;
    }
    const ByteBuffer *keyCert = key.GetCert();
    if (keyCert == nullptr) {
        LOG_ERROR(LABEL, "Get cert failed.");
        return CS_ERR_HUKS_OBTAIN_CERT;
    }
    if (!cert.CopyFrom(keyCert->GetBuffer(), keyCert->GetSize())) {
        return CS_ERR_MEMORY;
    }
    return CS_SUCCESS;
}
}
}
}
