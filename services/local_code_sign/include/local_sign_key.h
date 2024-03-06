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

#ifndef OHOS_LOCAL_SIGN_KEY_H
#define OHOS_LOCAL_SIGN_KEY_H

#include <memory>
#include <string>

#include "byte_buffer.h"
#include "errcode.h"
#include "hks_type.h"
#include "hks_api.h"
#include "hks_param.h"
#include "log.h"
#include "sign_key.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class LocalSignKey : public SignKey {
public:
    static LocalSignKey &GetInstance();
    const ByteBuffer *GetSignCert() override;
    bool Sign(const ByteBuffer &data, ByteBuffer &ret) override;
    const HksCertChain *GetCertChain();
    bool InitKey();
private:
    class HUKSParamSet {
    public:
        HUKSParamSet() : paramSet(nullptr)
        {
        }

        bool Init(const struct HksParam tmpParams[], uint32_t paramCount)
        {
            int32_t ret = HksInitParamSet(&paramSet);
            if (ret != HKS_SUCCESS) {
                LOG_ERROR("HksInitParamSet failed");
                return false;
            }
            ret = HksAddParams(paramSet, tmpParams, paramCount);
            if (ret != HKS_SUCCESS) {
                LOG_ERROR("HksAddParams failed");
                return false;
            }

            ret = HksBuildParamSet(&paramSet);
            if (ret != HKS_SUCCESS) {
                LOG_ERROR("HksBuildParamSet failed");
                return false;
            }
            return true;
        }

        HksParamSet *GetParamSet() const
        {
            return paramSet;
        }

        ~HUKSParamSet()
        {
            if (paramSet != nullptr) {
                HksFreeParamSet(&paramSet);
                paramSet = nullptr;
            }
        }
    private:
        HksParamSet *paramSet = nullptr;
    };

    LocalSignKey();
    ~LocalSignKey();

    LocalSignKey(const LocalSignKey &source) = delete;
    LocalSignKey &operator = (const LocalSignKey &source) = delete;

    bool GenerateKey();
    HksCertChain *QueryCertChain();
    bool GetKeyParamSet(HUKSParamSet &paramSet);
    bool GetAttestParamSet(HUKSParamSet &paramSet);
    bool GetSignParamSet(HUKSParamSet &paramSet);
    bool SignByHUKS(const struct HksBlob *inData, struct HksBlob *outData);

private:
    ByteBuffer *cert_ = nullptr;
    HksCertChain *certChain_ = nullptr;
    std::unique_ptr<uint8_t[]> challenge_ = nullptr;
    std::string algorithm_ = "ECDSA256";
};
}
}
}

#endif