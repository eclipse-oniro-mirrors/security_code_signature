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

#ifndef CODE_SIGNATURE_FUZZ_COMMON
#define CODE_SIGNATURE_FUZZ_COMMON
#include <vector>
#include <string>
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class SignInfoRandomGenerator {
public:
SignInfoRandomGenerator(const uint8_t *data, const size_t size) : data_(data), dataLenth_(size) {}
    template <class T> T GetData()
    {
        T object{};
        size_t objectSize = sizeof(object);
        if (data_ == nullptr || objectSize > dataLenth_ - basePos) {
            basePos = 0; // reset read point
            return object; // return empty obj
        }
        errno_t ret = memcpy_s(&object, objectSize, data_ + basePos, objectSize);
        if (ret != EOK) {
            return {};
        }
        basePos += objectSize;
        return object;
    }

    void GenerateFilePath(std::string &str);
    void GenerateString(std::string &str);
private:
    const uint8_t *data_;
    const size_t dataLenth_;
    size_t basePos = 0;
};
}
}
}
#endif