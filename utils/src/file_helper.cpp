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

#include "file_helper.h"

#include <climits>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <unistd.h>

#include "directory_ex.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
bool CheckFilePathValid(const std::string &path, const std::string &baseRealPath)
{
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        LOG_INFO("Get real path failed, path = %{public}s", path.c_str());
        return false;
    }
    return (realPath.size() > baseRealPath.size()) &&
        (realPath.compare(0, baseRealPath.size(), baseRealPath) == 0) &&
        (realPath[baseRealPath.size()] == '/');
}

bool ReadFileToString(const std::string &path, uint32_t maxSize, std::string &content)
{
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        LOG_ERROR("Get real path failed, path = %{public}s", path.c_str());
        return false;
    }
    std::ifstream ifs(realPath, std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        LOG_ERROR("Open file failed, path = %{public}s", realPath.c_str());
        return false;
    }
    ifs.seekg(0, std::ios::end);
    std::streamoff fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    if (fileSize < 0) {
        LOG_ERROR("Get file size failed, path = %{public}s", realPath.c_str());
        return false;
    }
    if (static_cast<uint64_t>(fileSize) > maxSize) {
        LOG_ERROR("File size exceeds limit, path = %{public}s", realPath.c_str());
        return false;
    }
    content.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (static_cast<std::streamoff>(content.size()) != fileSize) {
        LOG_ERROR("Read file incomplete, path = %{public}s", realPath.c_str());
        content.clear();
        return false;
    }
    return true;
}
}
}
}