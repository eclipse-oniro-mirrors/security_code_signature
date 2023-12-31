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

use std::fs::File;
use std::ffi::{c_char, CString};
use std::io::{BufRead, BufReader};
use std::option::Option;
use std::ptr;
use std::thread::sleep_ms;
use std::vec::Vec;

use hilog_rust::{error, hilog, HiLogLabel, LogType};
use super::cs_hisysevent;
use super::cert_utils;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN"
};

const CERT_DATA_MAX_SIZE: usize = 8192;
const PROC_KEY_FILE_PATH: &str = "/proc/keys";
const KEYRING_TYPE: &str = "keyring";
const FSVERITY_KEYRING_NAME: &str = ".fs-verity";
const LOCAL_KEY_NAME: &str = "local_key";
const CODE_SIGN_KEY_NAME_PREFIX: &str = "fs_verity_key";
const SUCCESS: i32 = 0;

// retry to get local cert
const LOCAL_CERT_MAX_RETRY_TIMES: i32 = 5;
const SLEEP_MILLI_SECONDS: u32 = 50;

type KeySerial = i32;

extern "C" {
    fn InitLocalCertificate(cert_data: *mut u8, cert_size: *mut usize) -> i32;
    fn AddKey(type_name: *const u8, description: *const u8, payload: *const u8,
        plen: usize, ring_id: KeySerial) -> KeySerial;
    fn KeyctlRestrictKeyring(ring_id: KeySerial, type_name: *const u8,
        restriction: *const u8) -> KeySerial;
}

fn get_local_key() -> Option<Vec<u8>>
{
    let mut cert_size = CERT_DATA_MAX_SIZE;
    let mut cert_data = Vec::with_capacity(cert_size);
    let pcert = cert_data.as_mut_ptr();
    unsafe {
        if InitLocalCertificate(pcert, &mut cert_size) == 0 {
            cert_data.set_len(cert_size);
            Some(cert_data)
        } else {
            None
        }
    }
}

/// parse key info
/// [Serial][Flags][Usage][Expiry][Permissions][UID][GID][TypeName][Description]: [Summary]
///   [0]     [1]    [2]    [3]       [4]       [5]  [6]     [7]        [8]         [9]
/// 3985ad4c I------  1    perm     082f0000     0    0    keyring  .fs-verity:   empty
fn parse_key_info(line: String) -> Option<KeySerial>
{
    let attrs: Vec<&str> = line.split_whitespace().collect();
    if attrs.len() != 10 {
        return None;
    }
    if attrs[7] == KEYRING_TYPE && attrs[8].strip_suffix(':') == Some(FSVERITY_KEYRING_NAME) {
        match KeySerial::from_str_radix(attrs[0], 16) {
            Ok(x) => Some(x),
            Err(error) => {
                error!(LOG_LABEL, "Convert KeySerial failed: {}", error);
                None
            }
        }
    } else {
        None
    }
}

fn enable_key(key_id: KeySerial, key_name: &str, cert_data: &Vec<u8>) -> i32
{
    let type_name = CString::new("asymmetric").expect("type name is invalid");
    let keyname = CString::new(key_name).expect("keyname is invalid");
    unsafe {
        let ret: i32 = AddKey(type_name.as_ptr(), keyname.as_ptr(), cert_data.as_ptr(), cert_data.len(), key_id);
        ret
    }
}

fn enable_key_list(key_id: KeySerial, certs: Vec<Vec<u8>>) -> i32
{
    let prefix = String::from(CODE_SIGN_KEY_NAME_PREFIX);
    for (i, cert_data) in certs.iter().enumerate() {
        let key_name = prefix.clone() + &i.to_string();
        let ret = enable_key(key_id, key_name.as_str(), cert_data);
        if ret < 0 {
            return ret;
        }
    }
    SUCCESS
}

/// parse proc_key_file to get keyring id
fn get_keyring_id() -> Result<KeySerial, ()>
{
    let file = File::open(PROC_KEY_FILE_PATH).expect("Open /proc/keys failed");
    let lines = BufReader::new(file).lines();
    for line in lines.flatten() {
        if line.contains(KEYRING_TYPE) && line.contains(FSVERITY_KEYRING_NAME) {
            if let Some(keyid) = parse_key_info(line) {
                return Ok(keyid);
            }
        }
    }
    error!(LOG_LABEL, "Get .fs-verity keyring id failed.");
    Err(())
}

// enable all trusted keys
fn enable_trusted_keys(key_id: KeySerial) -> Result<(), ()>
{
    let certs = cert_utils::get_trusted_certs();
    let ret = enable_key_list(key_id, certs);
    if ret < 0 {
        cs_hisysevent::report_add_key_err("code_sign_keys", ret);
        return Err(());
    }
    Ok(())
}

// enable local key from local code sign SA
fn enable_local_key(key_id: KeySerial) -> Result<(), ()>
{
    let mut times = 0;
    let cert_data = loop {
        match get_local_key() {
            Some(key) => {
                break key;
            },
            None => {
                error!(LOG_LABEL, "Get local key failed, may try again.");
            }
        }
        times += 1;
        if times == LOCAL_CERT_MAX_RETRY_TIMES {
            error!(LOG_LABEL, "Local key is not avaliable.");
            return Err(());
        }
        sleep_ms(SLEEP_MILLI_SECONDS);
    };
    let ret = enable_key(key_id, LOCAL_KEY_NAME, &cert_data);
    if ret < 0 {
        cs_hisysevent::report_add_key_err("local_key", ret);
        error!(LOG_LABEL, "Enable local key failed");
        return Err(());
    }
    Ok(())
}

// restrict fs-verity keyring, don't allow to add more keys
fn restrict_keys(key_id: KeySerial) -> Result<(), ()>
{
    unsafe {
        if KeyctlRestrictKeyring(key_id, ptr::null(), ptr::null()) < 0 {
            error!(LOG_LABEL, "Restrict keyring err");
            return Err(());
        }
    }
    Ok(())
}

/// enable trusted and local keys, and then restrict keyring
pub fn enable_all_keys() -> Result<(), ()>
{
    let key_id = get_keyring_id()?;
    enable_trusted_keys(key_id)?;
    enable_local_key(key_id)?;
    restrict_keys(key_id)?;
    Ok(())
}