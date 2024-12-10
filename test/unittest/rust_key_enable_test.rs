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
extern crate key_enable;
extern crate ylong_json;

use std::thread;
use ylong_json::JsonValue;
use key_enable::cert_chain_utils::PemCollection;
use key_enable::cert_path_utils::TrustCertPath;
use key_enable::profile_utils::{UDID, get_udid, validate_bundle_and_distribution_type};


// pem_cert_file
const VALID_PEM_CERT: &str = "/data/test/tmp/valid_pem_cert.json";
const NON_EXISTEND_PEM_CERT: &str = "/data/test/tmp/non_existent_cert_path.json";
const INVALID_STRUCTURE_PEM_CERT: &str = "/data/test/tmp/invalid_structure_cert_path.json";
const EMPTY_PEM_CERT: &str = "/data/test/tmp/empty_pem_cert.json";
// cert_path_file
const VALID_CERT_PATH: &str = "/data/test/tmp/valid_cert_path.json";
const NON_EXISTEND_CERT_PATH: &str = "/data/test/tmp/non_existent_cert_path.json";
const INVALID_STRUCTURE_CERT_PATH: &str = "/data/test/tmp/invalid_structure_cert_path.json";
const EMPTY_CERT_PATH: &str = "/data/test/tmp/empty_cert_path.json";

const ALLOWED_ROOT_CERT_MEMBER_NAMES: &[&str] = &[
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2",
    "C=CN, O=OpenHarmony, OU=OpenHarmony Team, CN=OpenHarmony Application Root CA",
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2 Test",
];

#[test]
fn test_load_pem_cert_from_valid_json_file() {
    // test is_debuggable true
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(VALID_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert_eq!(root_cert.pem_data.len(), 3);
}

#[test]
fn test_invalid_pem_cert_file_path() {
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(NON_EXISTEND_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_invalid_pem_cert_json_structure() {
    let mut root_cert = PemCollection::new();
    root_cert
        .load_pem_certs_from_json_file(INVALID_STRUCTURE_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_empty_pem_cert_json_file() {
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(EMPTY_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_successful_load_cert_path() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(VALID_CERT_PATH);
    assert_eq!(cert_paths.profile_signers.len(), 4);
    assert_eq!(cert_paths.app_sources.len(), 6);
}
#[test]
fn test_invalid_cert_path_file_path() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(NON_EXISTEND_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}

#[test]
fn test_invalid_cert_path_json_structure() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(INVALID_STRUCTURE_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}

#[test]
fn test_empty_cert_path_json_file() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(EMPTY_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}

#[test]
fn test_parse_enterprise_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_enterprise_normal_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise_normal",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise_normal",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_enterprise_mdm_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise_mdm",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise_mdm",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_debug_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "developer",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "debug",
        "bundle-info": {
            "developer-id": "",
            "development-certificate": "",
            "bundle-name": "com.test.developer",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut profile_json =JsonValue::from_text(profile_str).unwrap();
    profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid);
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_iternaltesting_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut profile_json =JsonValue::from_text(profile_str).unwrap();
    profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid);
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_invalid_profile() {
    let no_type_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let no_distribution_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let no_debug_info_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut no_type_profile_json =JsonValue::from_text(no_type_profile).unwrap();
    no_type_profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid.clone());
    let result = validate_bundle_and_distribution_type(&no_type_profile_json, true);
    assert!(result.is_err());

    let mut no_distribution_profile_json =JsonValue::from_text(no_distribution_profile).unwrap();
    no_distribution_profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid.clone());
    let result = validate_bundle_and_distribution_type(&no_distribution_profile_json, true);
    assert!(result.is_err());

    let no_debug_info_profile_json =JsonValue::from_text(no_debug_info_profile).unwrap();
    let result = validate_bundle_and_distribution_type(&no_debug_info_profile_json, true);
    assert!(result.is_err());
}

#[test]
fn test_get_udid_once() {
    let udid_from_get = get_udid().expect("Failed to get UDID");
    let udid_from_global = UDID.clone().expect("UDID is None");

    assert_eq!(udid_from_get, udid_from_global);
}

#[test]
fn test_get_udid_concurrent() {
    let num_threads = 10;
    let mut handles = vec![];

    for _ in 0..num_threads {
        let handle = thread::spawn(|| {
            let udid = get_udid().expect("Failed to get UDID");
            assert_eq!(udid, UDID.clone().expect("UDID is None"));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}