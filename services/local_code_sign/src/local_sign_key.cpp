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

#include "local_sign_key.h"

#include <cstring>
#include <cstdio>
#include <climits>
#include <openssl/rand.h>
#include <string>

#include "byte_buffer.h"
#include "cert_utils.h"
#include "errcode.h"
#include "log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string ALIAS_NAME = "LOCAL_SIGN_KEY";
static const struct HksBlob LOCAL_SIGN_KEY_ALIAS = { ALIAS_NAME.size(), (uint8_t *)ALIAS_NAME.c_str()};
static const uint32_t CHALLENGE_LEN = 32;

static const struct HksParam ECC_KEY_PRARAM[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 }
};

LocalSignKey &LocalSignKey::GetInstance()
{
    static LocalSignKey singleLocalSignKey;
    return singleLocalSignKey;
}

LocalSignKey::LocalSignKey()
{
}

LocalSignKey::~LocalSignKey()
{
    if (cert_ != nullptr) {
        delete cert_;
        cert_ = nullptr;
    }
    if (certChain_ != nullptr) {
        FreeCertChain(&certChain_, certChain_->certsCount);
        certChain_ = nullptr;
    }
}

bool LocalSignKey::InitKey()
{
    int ret = HksKeyExist(&LOCAL_SIGN_KEY_ALIAS, nullptr);
    if (ret == HKS_ERROR_NOT_EXIST) {
        if (!GenerateKey()) {
            return false;
        }
    } else if (ret != HKS_SUCCESS) {
        LOG_ERROR(LABEL, "HksKeyExist fail, ret is %{public}d!", ret);
        return false;
    }
    return true;
}

const ByteBuffer *LocalSignKey::GetCert()
{
    if (cert_ != nullptr) {
        return cert_;
    }
    const HksCertChain *certChain = GetCertChain();
    cert_ = new (std::nothrow) ByteBuffer();
    if (cert_ == nullptr) {
        LOG_ERROR(LABEL, "Alloc memory for cert blob failed.");
        return nullptr;
    }
    if (!cert_->CopyFrom(certChain->certs[0].data, certChain->certs[0].size)) {
        delete cert_;
    }
    return cert_;
}

const HksCertChain *LocalSignKey::GetCertChain()
{
    if (certChain_ != nullptr) {
        return certChain_;
    }
    certChain_ = QueryCertChain();
    if (certChain_ == nullptr) {
        LOG_ERROR(LABEL, "QueryCertChain failed.");
        return nullptr;
    }
    return certChain_;
}
HksCertChain *LocalSignKey::QueryCertChain()
{
    // init attest param
    HUKSParamSet paramSet;
    if (!GetAttestParamSet(paramSet)) {
        return nullptr;
    }

    HksCertChain *certChain = nullptr;
    // alloc memory for cert chain
    if (!ConstructDataToCertChain(&certChain)) {
        return nullptr;
    }

    // get cert chain by huks attest
    int ret = HksAttestKey(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet(), certChain);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR(LABEL, "HksAttestKey fail, ret is %{public}d!", ret);
        return nullptr;
    }
    return certChain;
}

bool LocalSignKey::GetKeyParamSet(HUKSParamSet &paramSet)
{
    if (algorithm_.compare("ECDSA256") == 0) {
        return paramSet.Init(ECC_KEY_PRARAM, sizeof(ECC_KEY_PRARAM) / sizeof(HksParam));
    }
    return false;
}

bool LocalSignKey::GetAttestParamSet(HUKSParamSet &paramSet)
{
    // init challenge data by secure random function
    if (challenge_ == nullptr) {
        challenge_ = std::make_unique<uint8_t[]>(CHALLENGE_LEN);
        if (challenge_ == nullptr) {
            return false;
        }
        RAND_bytes(challenge_.get(), CHALLENGE_LEN);
    }
    struct HksBlob challengeBlob = {
        .size = CHALLENGE_LEN,
        .data = challenge_.get()
    };
    struct HksParam attestationParams[] = {
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = challengeBlob },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = LOCAL_SIGN_KEY_ALIAS },
    };
    return paramSet.Init(attestationParams, sizeof(attestationParams) / sizeof(HksParam));
}

bool LocalSignKey::GenerateKey()
{
    HUKSParamSet paramSet;
    if (!GetKeyParamSet(paramSet)) {
        return false;
    }
    int ret = HksGenerateKey(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet(), nullptr);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR(LABEL, "HksGenerateKey failed, ret is %{public}d!", ret);
        return false;
    }
    return true;
}
}
}
}
