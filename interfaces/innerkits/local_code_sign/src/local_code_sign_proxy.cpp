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

#include "local_code_sign_proxy.h"

#include "errcode.h"
#include "ipc_types.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t MAX_REPLY_BUFFER_SIZE = 65536;

int32_t LocalCodeSignProxy::InitLocalCertificate(ByteBuffer &cert)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return CS_ERR_REMOTE_CONNECTION;
    }
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (remote->SendRequest(static_cast<uint32_t>(LocalCodeSignInterfaceCode::INIT_LOCAL_CERTIFICATE),
        data, reply, option) != NO_ERROR) {
        return CS_ERR_IPC_MSG_INVALID;
    }
    return ReadResultFromReply(reply, cert);
}

int32_t LocalCodeSignProxy::SignLocalCode(const std::string &filePath, ByteBuffer &signature)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return CS_ERR_REMOTE_CONNECTION;
    }
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_ERROR(LABEL, "Write interface token failed.");
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteString(filePath)) {
        LOG_ERROR(LABEL, "Write string failed.");
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (remote->SendRequest(static_cast<uint32_t>(LocalCodeSignInterfaceCode::SIGN_LOCAL_CODE),
        data, reply, option) != NO_ERROR) {
        return CS_ERR_IPC_MSG_INVALID;
    }
    return ReadResultFromReply(reply, signature);
}

int32_t LocalCodeSignProxy::ReadResultFromReply(MessageParcel &reply, ByteBuffer &buffer)
{
    int32_t result;
    if (!reply.ReadInt32(result)) {
        return CS_ERR_IPC_READ_DATA;
    }
    if (result != CS_SUCCESS) {
        return result;
    }
    uint32_t size;
    if (!reply.ReadUint32(size)) {
        return CS_ERR_IPC_READ_DATA;
    }
    if (size > MAX_REPLY_BUFFER_SIZE) {
        LOG_ERROR(LABEL, "Invalid reply data size.");
        return CS_ERR_IPC_MSG_INVALID;
    }
    const uint8_t *outData = reply.ReadBuffer(size);
    if (outData == nullptr) {
        return CS_ERR_IPC_MSG_INVALID;
    }
    if (!buffer.CopyFrom(outData, size)) {
        return CS_ERR_MEMORY;
    }
    return CS_SUCCESS;
}
}
}
}

