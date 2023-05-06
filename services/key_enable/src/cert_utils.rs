/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

use std::fs::File;
use std::io::{Read};

const TRUSTED_CERT_FILE_PATH: &str = "/system/etc/security/trusted_code_signature_ca.cer";

// compatible with multiple certs
pub fn get_trusted_certs() -> Vec<Vec<u8>>
{
    // now only one certificate in der format stored in file
    let mut file = File::open(TRUSTED_CERT_FILE_PATH).expect("Open cert file failed.");
    let mut der = Vec::new();
    file.read_to_end(&mut der).expect("Read file failed.");
    let certs = vec![der];
    certs
}