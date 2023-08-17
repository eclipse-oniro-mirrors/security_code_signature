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

use std::ffi::{c_char, CString};
use hilog_rust::{error, hilog, HiLogLabel, LogType};

use super::cert_chain_utils;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN"
};

const CODE_SIGNATURE_TRUSTED_CERTS: &str = "/system/etc/security/trusted_code_signature_certs.cer";
const CODE_SIGNATURE_TRUSTED_TEST_CERTS: &str = "/system/etc/security/trusted_code_signature_test_certs.cer";

fn get_trusted_cert_from_file(certs: &mut Vec<Vec<u8>>, file_path: &str)
{
    match cert_chain_utils::get_verifed_cert_from_chain(file_path) {
        Some(der) => {
            certs.push(der);
        },
        None => {
            error!(LOG_LABEL, "Get trusted cert failed.");
        }
    }
}

// compatible with multiple CA
pub fn get_trusted_certs() -> Vec<Vec<u8>>
{
    let mut certs = Vec::new();
    get_trusted_cert_from_file(&mut certs, CODE_SIGNATURE_TRUSTED_CERTS);
    if env!("code_signature_debuggable") == "on" {
        get_trusted_cert_from_file(&mut certs, CODE_SIGNATURE_TRUSTED_TEST_CERTS);
    }
    certs
}