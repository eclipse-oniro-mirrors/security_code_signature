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

use lazy_static::lazy_static;
use super::cert_chain_utils::PemCollection;
use super::cert_path_utils::{
    add_cert_path_info, remove_cert_path_info, common_format_fabricate_name,
    DebugCertPathType, ReleaseCertPathType, TrustCertPath,
};
use super::cs_hisysevent::report_parse_profile_err;
use super::file_utils::{
    create_file_path, delete_file_path, file_exists, fmt_store_path,
    load_bytes_from_file, write_bytes_to_file, change_default_mode_file, change_default_mode_directory
};
use hilog_rust::{error, info, hilog, HiLogLabel, LogType};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509NameRef, X509};
use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::fs::read_dir;
use ylong_json::JsonValue;

const ERROR_CODE: i32 = -1;
const SUCCESS_CODE: i32 = 0;
const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd005a06, // security domain
    tag: "CODE_SIGN",
};
const PROFILE_STORE_EL0_PREFIX: &str = "/data/service/el0/profiles/developer";
const PROFILE_STORE_EL1_PREFIX: &str = "/data/service/el1/profiles/release";
const PROFILE_STORE_EL1_PUBLIC_PREFIX: &str = "/data/service/el1/public/profiles/release";
const DEBUG_PROFILE_STORE_EL0_PREFIX: &str = "/data/service/el0/profiles/debug";
const DEBUG_PROFILE_STORE_EL1_PREFIX: &str = "/data/service/el1/profiles/debug";
const DEBUG_PROFILE_STORE_EL1_PUBLIC_PREFIX: &str = "/data/service/el1/public/profiles/debug";
const PROFILE_STORE_TAIL: &str = "profile.p7b";
const PROFILE_TYPE_KEY: &str = "type";
const PROFILE_DEVICE_ID_TYPE_KEY: &str = "device-id-type";
const PROFILE_DEBUG_INFO_KEY: &str = "debug-info";
const PROFILE_DEVICE_IDS_KEY: &str = "device-ids";
const PROFILE_BUNDLE_INFO_KEY: &str = "bundle-info";
const PROFILE_BUNDLE_INFO_RELEASE_KEY: &str = "distribution-certificate";
const PROFILE_BUNDLE_INFO_DEBUG_KEY: &str = "development-certificate";
const PROFILE_APP_DISTRIBUTION_TYPE_KEY: &str = "app-distribution-type";
const APP_DISTRIBUTION_TYPE_INTERNALTESTING: &str = "internaltesting";
const APP_DISTRIBUTION_TYPE_ENTERPRISE: &str = "enterprise";
const APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL: &str = "enterprise_normal";
const APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM: &str = "enterprise_mdm";
const DEFAULT_MAX_CERT_PATH_LEN: u32 = 3;
const PROFILE_RELEASE_TYPE: &str = "release";
const PROFILE_DEBUG_TYPE: &str = "debug";

/// profile error
pub enum ProfileError {
    /// add cert path error
    AddCertPathError,
}
/// profile error report to hisysevent
pub enum HisyseventProfileError {
    /// release platform code
    VerifySigner = 1,
    /// release authed code
    ParsePkcs7 = 2,
    /// release developer code
    AddCertPath = 3,
}

extern "C" {
    /// if developer state on return true
    pub fn IsDeveloperModeOn() -> bool;
    fn CodeSignGetUdid(udid: *mut u8) -> i32;
    fn IsRdDevice() -> bool;
}

#[no_mangle]
/// the interface to enable key in profile
pub extern "C" fn EnableKeyInProfileByRust(
    bundle_name: *const c_char,
    profile: *const u8,
    profile_size: u32,
) -> i32 {
    match enable_key_in_profile_internal(bundle_name, profile, profile_size) {
        Ok(_) => SUCCESS_CODE,
        Err(_) => ERROR_CODE,
    }
}

#[no_mangle]
/// the interface remove key in profile
pub extern "C" fn RemoveKeyInProfileByRust(bundle_name: *const c_char) -> i32 {
    match remove_key_in_profile_internal(bundle_name) {
        Ok(_) => SUCCESS_CODE,
        Err(_) => ERROR_CODE,
    }
}

fn parse_pkcs7_data(
    pkcs7: &Pkcs7,
    root_store: &X509Store,
    flags: Pkcs7Flags,
    check_udid: bool,
) -> Result<(String, String, u32), Box<dyn Error>> {
    let profile = verify_pkcs7_signature(pkcs7, root_store, flags)?;
    let profile_json = parse_and_validate_profile(profile, check_udid)?;
    get_cert_details(&profile_json)
}

fn verify_pkcs7_signature(
    pkcs7: &Pkcs7,
    root_store: &X509Store,
    flags: Pkcs7Flags,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let stack_of_certs = Stack::<X509>::new()?;
    let mut profile = Vec::new();
    pkcs7.verify(&stack_of_certs, root_store, None, Some(&mut profile), flags)?;
    Ok(profile)
}

/// validate bundle info and debug info
pub fn validate_bundle_and_distribution_type(
    profile_json: &JsonValue,
    check_udid: bool,
) -> Result<(), Box<dyn Error>> {
    let bundle_type = profile_json[PROFILE_TYPE_KEY].try_as_string()?.as_str();
    match bundle_type {
        PROFILE_DEBUG_TYPE => {
            if check_udid && verify_udid(profile_json).is_err() {
                return Err("Invalid UDID.".into());
            }
        },
        PROFILE_RELEASE_TYPE => {
            let distribution_type = profile_json[PROFILE_APP_DISTRIBUTION_TYPE_KEY].try_as_string()?.as_str();
            match distribution_type {
                APP_DISTRIBUTION_TYPE_INTERNALTESTING => {
                    if check_udid && verify_udid(profile_json).is_err() {
                        return Err("Invalid UDID.".into());
                    }
                },
                APP_DISTRIBUTION_TYPE_ENTERPRISE |
                APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL |
                APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM => {
                },
                _ => {
                    return Err("Invalid app distribution type.".into());
                }
            }
        }
        _ => {
            return Err("Invalid bundle type.".into());
        },
    }
    Ok(())
}

fn parse_and_validate_profile(
    profile: Vec<u8>,
    check_udid: bool,
) -> Result<JsonValue, Box<dyn Error>> {
    let profile_json = JsonValue::from_text(profile)?;
    validate_bundle_and_distribution_type(&profile_json, check_udid)?;
    Ok(profile_json)
}

fn get_cert_details(profile_json: &JsonValue) -> Result<(String, String, u32), Box<dyn Error>> {
    let bundle_type = profile_json[PROFILE_TYPE_KEY].try_as_string()?.as_str();
    let profile_type = match bundle_type {
        PROFILE_DEBUG_TYPE => DebugCertPathType::Developer as u32,
        PROFILE_RELEASE_TYPE => ReleaseCertPathType::Developer as u32,
        _ => return Err("Invalid bundle type.".into()),
    };
    let signed_cert = match bundle_type {
        PROFILE_DEBUG_TYPE => profile_json[PROFILE_BUNDLE_INFO_KEY][PROFILE_BUNDLE_INFO_DEBUG_KEY].try_as_string()?,
        PROFILE_RELEASE_TYPE => profile_json[PROFILE_BUNDLE_INFO_KEY][PROFILE_BUNDLE_INFO_RELEASE_KEY].try_as_string()?,
        _ => return Err("Invalid bundle type.".into()),
    };
    let signed_pem = X509::from_pem(signed_cert.as_bytes())?;
    let subject = format_x509_fabricate_name(signed_pem.subject_name());
    let issuer = format_x509_fabricate_name(signed_pem.issuer_name());
    Ok((subject, issuer, profile_type))
}

lazy_static! {
    /// global udid
    pub static ref UDID: Result<String, String> = init_udid();
}

fn init_udid() -> Result<String, String> {
    let mut udid: Vec<u8> = vec![0; 128];
    let result = unsafe { CodeSignGetUdid(udid.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to get UDID".to_string());
    }

    if let Some(first_zero_index) = udid.iter().position(|&x| x == 0) {
        udid.truncate(first_zero_index);
    }

    match String::from_utf8(udid) {
        Ok(s) => Ok(s),
        Err(_) => Err("UDID is not valid UTF-8".to_string()),
    }
}

/// get device udid
pub fn get_udid() -> Result<String, String> {
    UDID.clone()
}


fn verify_signers(
    pkcs7: &Pkcs7,
    profile_signer: &[(&String, &String)],
) -> Result<(), Box<dyn Error>> {
    let stack_of_certs = Stack::<X509>::new()?;
    let signers_result = pkcs7.signers(&stack_of_certs, Pkcs7Flags::empty())?;
    for signer in signers_result {
        let subject_name = format_x509name_to_string(signer.subject_name());
        let issuer_name = format_x509name_to_string(signer.issuer_name());
        if !profile_signer.contains(&(&subject_name, &issuer_name)) {
            return Err("Verification failed.".into());
        }
    }
    Ok(())
}

fn format_x509name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();

    for entry in name.entries() {
        let tag = match entry.object().nid() {
            openssl::nid::Nid::COMMONNAME => "CN",
            openssl::nid::Nid::COUNTRYNAME => "C",
            openssl::nid::Nid::ORGANIZATIONNAME => "O",
            openssl::nid::Nid::ORGANIZATIONALUNITNAME => "OU",
            _ => continue,
        };
        let value = entry.data().as_utf8().unwrap();
        parts.push(format!("{}={}", tag, value));
    }
    parts.join(", ")
}

fn format_x509_fabricate_name(name: &X509NameRef) -> String {
    let mut common_name = String::new();
    let mut organization = String::new();
    let mut email = String::new();

    for entry in name.entries() {
        let entry_nid = entry.object().nid();
        if let Ok(value) = entry.data().as_utf8() {
            match entry_nid {
                openssl::nid::Nid::COMMONNAME => common_name = value.to_string(),
                openssl::nid::Nid::ORGANIZATIONNAME => organization = value.to_string(),
                openssl::nid::Nid::PKCS9_EMAILADDRESS => email = value.to_string(),
                _ => continue,
            };
        }
    }
    let ret = common_format_fabricate_name(&common_name, &organization, &email);
    ret
}

fn get_profile_paths(is_debug: bool) -> Vec<String> {
    let mut paths = Vec::new();
    let profile_prefixes = match is_debug {
        false => vec![PROFILE_STORE_EL0_PREFIX, PROFILE_STORE_EL1_PREFIX, PROFILE_STORE_EL1_PUBLIC_PREFIX],
        true => vec![DEBUG_PROFILE_STORE_EL0_PREFIX, DEBUG_PROFILE_STORE_EL1_PREFIX, DEBUG_PROFILE_STORE_EL1_PUBLIC_PREFIX],
    };
    for profile_prefix in profile_prefixes {
        paths.extend(get_paths_from_prefix(profile_prefix));
    }
    paths
}

fn get_paths_from_prefix(prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(entries) = read_dir(prefix) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let filename = fmt_store_path(&path.to_string_lossy(), PROFILE_STORE_TAIL);
            if file_exists(&filename) {
                paths.push(filename);
            }
        }
    }
    paths
}

/// add profile cert path data
pub fn add_profile_cert_path(
    root_cert: &PemCollection,
    cert_paths: &TrustCertPath,
) -> Result<(), ProfileError> {
    let x509_store = root_cert.to_x509_store().unwrap();
    if process_profile(false, &x509_store, cert_paths.get_profile_info().as_slice()).is_err() {
        return Err(ProfileError::AddCertPathError);
    }
    if process_profile(true, &x509_store, cert_paths.get_debug_profile_info().as_slice()).is_err() {
        return Err(ProfileError::AddCertPathError);
    }
    Ok(())
}

fn process_profile(
    is_debug: bool,
    x509_store: &X509Store,
    profile_info: &[(&String, &String)],
) -> Result<(), ProfileError> {
    let profiles_paths = get_profile_paths(is_debug);
    for path in profiles_paths {
        let mut pkcs7_data = Vec::new();
        if load_bytes_from_file(&path, &mut pkcs7_data).is_err() {
            info!(LOG_LABEL, "load profile failed {}!", @public(path));
            continue;
        }
        info!(LOG_LABEL, "load profile success {}!", @public(path));
        let pkcs7 = match Pkcs7::from_der(&pkcs7_data) {
            Ok(pk7) => pk7,
            Err(_) => {
                error!(LOG_LABEL, "load profile to pkcs7 obj failed {}!", @public(path));
                continue;
            }
        };
        if verify_signers(&pkcs7, profile_info).is_err() {
            error!(LOG_LABEL, "Invalid signer profile file {}", @public(path));
            report_parse_profile_err(&path, HisyseventProfileError::VerifySigner as i32);
            continue;
        }
        let check_udid = unsafe { !IsRdDevice() };
        let (subject, issuer, profile_type) =
            match parse_pkcs7_data(&pkcs7, x509_store, Pkcs7Flags::empty(), check_udid) {
                Ok(tuple) => tuple,
                Err(e) => {
                    error!(LOG_LABEL, "Error parsing PKCS7 data: {}, profile file {}",
                        @public(e), @public(path));
                    report_parse_profile_err(&path, HisyseventProfileError::ParsePkcs7 as i32);
                    continue;
                }
            };
        if add_cert_path_info(subject, issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
            error!(
                LOG_LABEL,
                "Failed to add profile cert path info into ioctl for {}", @public(path)
            );
            report_parse_profile_err(&path, HisyseventProfileError::AddCertPath as i32);
            continue;
        }
    }
    Ok(())
}

fn verify_udid(profile_json: &JsonValue) -> Result<(), String> {
    let device_udid = get_udid()?;
    info!(LOG_LABEL, "get device udid {}!", device_udid);
    let device_id_type = &profile_json[PROFILE_DEBUG_INFO_KEY][PROFILE_DEVICE_ID_TYPE_KEY];

    if let JsonValue::String(id_type) = device_id_type {
        if id_type != "udid" {
            return Err("Invalid device ID type".to_string());
        }
    } else {
        return Err("Device ID type is not a string".to_string());
    }
    match &profile_json[PROFILE_DEBUG_INFO_KEY][PROFILE_DEVICE_IDS_KEY] {
        JsonValue::Array(arr) => {
            if arr.iter().any(|item| match item {
                JsonValue::String(s) => s == &device_udid,
                _ => false,
            }) {
                Ok(())
            } else {
                Err("UDID not found in the list".to_string())
            }
        }
        _ => Err("Device IDs are not in an array format".to_string()),
    }
}

fn validate_and_convert_inputs(
    bundle_name: *const c_char,
    profile: *const u8,
    profile_size: u32,
) -> Result<(String, Vec<u8>), ()> {
    let _bundle_name = c_char_to_string(bundle_name);
    if _bundle_name.is_empty() {
        error!(LOG_LABEL, "invalid profile bundle name!");
        return Err(());
    }
    let profile_data = cbyte_buffer_to_vec(profile, profile_size);
    Ok((_bundle_name, profile_data))
}

fn process_data(profile_data: &[u8]) -> Result<(String, String, u32), ()> {
    let store = match X509StoreBuilder::new() {
        Ok(store) => store.build(),
        Err(_) => {
            error!(LOG_LABEL, "Failed to build X509 store");
            return Err(());
        }
    };

    let pkcs7 = match Pkcs7::from_der(profile_data) {
        Ok(pk7) => pk7,
        Err(_) => {
            error!(LOG_LABEL, "load profile to pkcs7 obj failed");
            return Err(());
        }
    };

    match parse_pkcs7_data(&pkcs7, &store, Pkcs7Flags::NOVERIFY, false) {
        Ok(tuple) => Ok(tuple),
        Err(_) => {
            error!(LOG_LABEL, "parse pkcs7 data error");
            Err(())
        }
    }
}

fn create_bundle_path(bundle_name: &str, profile_type: u32) -> Result<String, ()> {
    let bundle_path = match profile_type {
        value if value == DebugCertPathType::Developer as u32 => {
            fmt_store_path(DEBUG_PROFILE_STORE_EL1_PUBLIC_PREFIX, bundle_name)
        }
        value if value == ReleaseCertPathType::Developer as u32 => {
            fmt_store_path(PROFILE_STORE_EL1_PUBLIC_PREFIX, bundle_name)
        }
        _ => {
            error!(LOG_LABEL, "invalid profile type");
            return Err(());
        }
    };
    Ok(bundle_path)
}

fn enable_key_in_profile_internal(
    bundle_name: *const c_char,
    profile: *const u8,
    profile_size: u32,
) -> Result<(), ()> {
    let (_bundle_name, profile_data) = validate_and_convert_inputs(bundle_name, profile, profile_size)?;
    let (subject, issuer, profile_type) = process_data(&profile_data)?;
    let bundle_path = create_bundle_path(&_bundle_name, profile_type)?;
    info!(LOG_LABEL, "create bundle_path path {}!", @public(bundle_path));
    if !file_exists(&bundle_path) && create_file_path(&bundle_path).is_err() {
        error!(LOG_LABEL, "create bundle_path path {} failed!", @public(bundle_path));
        return Err(());
    }
    if change_default_mode_directory(&bundle_path).is_err() {
        error!(LOG_LABEL, "change bundle_path mode error!");
        return Err(());
    }
    let filename = fmt_store_path(&bundle_path, PROFILE_STORE_TAIL);
    if write_bytes_to_file(&filename, &profile_data).is_err() {
        error!(LOG_LABEL, "dump profile data error!");
        return Err(());
    }
    if change_default_mode_file(&filename).is_err() {
        error!(LOG_LABEL, "change profile mode error!");
        return Err(());
    }
    if add_cert_path_info(subject, issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
        error!(LOG_LABEL, "add profile data error!");
        return Err(());
    }
    info!(LOG_LABEL, "finish add cert path in ioctl!");
    Ok(())
}

fn process_remove_bundle(
    prefix: &str,
    bundle_name: &str,
) -> Result<(), ()> {
    let bundle_path = fmt_store_path(prefix, bundle_name);

    if !file_exists(&bundle_path) {
        return Err(());
    }

    let filename = fmt_store_path(&bundle_path, PROFILE_STORE_TAIL);
    let mut profile_data = Vec::new();
    if load_bytes_from_file(&filename, &mut profile_data).is_err() {
        error!(LOG_LABEL, "load profile data error!");
        return Err(());
    }

    let (subject, issuer, profile_type) = process_data(&profile_data)?;
    if delete_file_path(&bundle_path).is_err() {
        error!(LOG_LABEL, "remove profile data error!");
        return Err(());
    }

    info!(LOG_LABEL, "remove bundle_path path {}!", @public(bundle_path));

    if remove_cert_path_info(subject, issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
        error!(LOG_LABEL, "remove profile data error!");
        return Err(());
    }

    info!(LOG_LABEL, "finish remove cert path in ioctl!");
    Ok(())
}

fn remove_key_in_profile_internal(bundle_name: *const c_char) -> Result<(), ()> {
    let _bundle_name = c_char_to_string(bundle_name);
    if _bundle_name.is_empty() {
        error!(LOG_LABEL, "Invalid bundle name");
        return Err(());
    }

    let profile_prefix = vec![
        DEBUG_PROFILE_STORE_EL0_PREFIX,
        PROFILE_STORE_EL0_PREFIX,
        DEBUG_PROFILE_STORE_EL1_PREFIX,
        PROFILE_STORE_EL1_PREFIX,
        DEBUG_PROFILE_STORE_EL1_PUBLIC_PREFIX,
        PROFILE_STORE_EL1_PUBLIC_PREFIX,
    ];

    let mut rm_succ = false;
    for prefix in profile_prefix {
        if process_remove_bundle(prefix, &_bundle_name).is_ok() {
            rm_succ = true;
        }
    }
    if rm_succ {
        Ok(())
    } else {
        error!(LOG_LABEL, "Failed to remove bundle profile info, bundleName: {}.", @public(_bundle_name));
        Err(())
    }
}

fn c_char_to_string(c_str: *const c_char) -> String {
    unsafe {
        if c_str.is_null() {
            return String::new();
        }
        let c_str = CStr::from_ptr(c_str);
        c_str.to_string_lossy().to_string()
    }
}

fn cbyte_buffer_to_vec(data: *const u8, size: u32) -> Vec<u8> {
    unsafe {
        if data.is_null() {
            return Vec::new();
        }
        let data_slice = std::slice::from_raw_parts(data, size as usize);
        let mut result = Vec::with_capacity(size as usize);
        result.extend_from_slice(data_slice);
        result
    }
}
