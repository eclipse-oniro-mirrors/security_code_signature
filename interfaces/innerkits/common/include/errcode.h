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

#ifndef CODE_SIGN_ERR_CODE_H
#define CODE_SIGN_ERR_CODE_H

namespace OHOS {
namespace Security {
namespace CodeSign {
enum CommonErrCode {
    CS_SUCCESS = 0,
    CS_ERR_MEMORY = -0x1,
    CS_ERR_NO_PERMISSION = -0x2,
    CS_ERR_NO_SIGNATURE = -0x3,
    CS_ERR_INVALID_SIGNATURE = -0x4
};

enum FileOperationErrCode {
    CS_ERR_FILE_INVALID = -0x100,
    CS_ERR_FILE_PATH = -0x101,
    CS_ERR_FILE_OPEN = -0x102,
    CS_ERR_FILE_READ = -0x103,
    CS_ERR_EXTRACT_FILES = -0x104
};

enum SignErrCode {
    CS_ERR_PARAM_INVALID = -0x200,
    CS_ERR_HUKS_OBTAIN_CERT = -0x201,
    CS_ERR_HUKS_SIGN = -0x202,
    CS_ERR_HUKS_INIT_KEY = -0x203,
    CS_ERR_COMPUTE_DIGEST = -0x204
};

enum OpenSSLErrCode {
    CS_ERR_OPENSSL_LOAD_CERT = -0x210,
    CS_ERR_OPENSSL_CREATE_PKCS7_DATA = -0x211,
    CS_ERR_OPENSSL_PKCS7 = -0x212
};

enum FsverityErrCode {
    CS_ERR_ENABLE = -0x300,
    CS_ERR_FSVREITY_NOT_SUPPORTED = -0x301,
    CS_ERR_FSVERITY_NOT_ENABLED = -0x302
};

enum IPCErrCode {
    CS_ERR_IPC_MSG_INVALID = -0x500,
    CS_ERR_IPC_WRITE_DATA = -0x501,
    CS_ERR_IPC_READ_DATA = -0x502,
    CS_ERR_REMOTE_CONNECTION = -0x503,
    CS_ERR_SA_GET_SAMGR = -0x504,
    CS_ERR_SA_GET_PROXY = -0x505,
    CS_ERR_SA_LOAD_FAILED = -0x506,
    CS_ERR_SA_LOAD_TIMEOUT = -0x507
};
}
}
}
#endif