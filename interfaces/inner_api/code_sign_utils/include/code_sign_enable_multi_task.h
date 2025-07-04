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

#ifndef CODE_SIGN_ENABLE_MULTI_TASK_H
#define CODE_SIGN_ENABLE_MULTI_TASK_H

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <linux/fsverity.h>

#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
typedef int32_t CallbackFunc(const std::string &path, const struct code_sign_enable_arg &arg);

class CodeSignEnableMultiTask {
public:
    CodeSignEnableMultiTask();
    ~CodeSignEnableMultiTask();
    /**
     * @brief Add task data for code signing
     * @param targetFile hap or so real path on disk
     * @param code_sign_enable_arg arg
     */
    void AddTaskData(const std::string &targetFile, const struct code_sign_enable_arg &arg);
    /**
     * @brief Execute code signature addition task
     * @param ownerId app-identifier of the signature
     * @param pluginId plugin-identifier of the signature
     * @param path hap real path on disk
     * @param func Callback enable function
     * @return err code, see err_code.h
     */
    int32_t ExecuteEnableCodeSignTask(const std::string &ownerId, const std::string &pluginId,
        const std::string &path, CallbackFunc &func);
    /**
     * @brief Check whether file is verity enabled by fd
     * @param fd file descriptor
     * @return err code, see err_code.h
     */
    static int32_t IsFsVerityEnabled(int fd);
private:
    static int32_t IsFsVerityEnabled(const std::string &path);
    void SortTaskData();
    void ExecuteEnableCodeSignTask(uint32_t &index, int32_t &taskRet, const std::string &ownerId,
        const std::string &pluginId, const std::string &path, CallbackFunc &func);
    int32_t CheckOwnerId(const std::string &path, const std::string &ownerId,
        const uint8_t *sigPtr, uint32_t sigSize);
    int32_t CheckPluginId(const std::string &path, const std::string &pluginId,
        const uint8_t *sigPtr, uint32_t sigSize);
private:
    std::mutex cvLock_;
    std::condition_variable taskfinish_;
    std::vector<std::pair<std::string, code_sign_enable_arg >> enableData_;
    OHOS::ThreadPool enableCodeSignTaskWorker_;
    uint32_t taskCallBack_;
};
}
}
}

#endif