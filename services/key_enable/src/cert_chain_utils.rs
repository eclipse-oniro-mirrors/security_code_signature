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

use openssl::x509::{X509, X509StoreContext, X509VerifyResult};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::stack::Stack;
use openssl::error::ErrorStack;
use std::ffi::{c_char, CString};
use hilog_rust::{error, info, hilog, HiLogLabel, LogType};
use super::file_utils;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN"
};

fn print_openssl_error_stack(error_stack: ErrorStack)
{
    for error in error_stack.errors() {
        error!(LOG_LABEL, "{}", @public(error.to_string()));
    }
}

fn load_certs_from_pem_file(file_path: &str) -> Option<Vec<X509>>
{
    let pem = file_utils::load_bytes_from_file(file_path);
    match X509::stack_from_pem(&pem) {
        Ok(certs) => Some(certs),
        Err(e) => {
            print_openssl_error_stack(e);
            None
        }
    }
}

fn dump_cert_in_der(cert: X509) -> Option<Vec<u8>>
{
    match cert.to_der() {
        Ok(der) => Some(der),
        Err(e) => {
            print_openssl_error_stack(e);
            None
        }
    }
}

fn convert_to_stack(certs: Vec<X509>) -> Stack<X509>
{
    let mut stack_of_certs = Stack::<X509>::new().expect("Create Stack<X509> failed");
    for cert in certs {
        stack_of_certs.push(cert).unwrap();
    }
    stack_of_certs
}

fn convert_to_store(certs: Vec<X509>) -> X509Store
{
    let mut store_builder = X509StoreBuilder::new().expect("Create X509StoreBuilder failed");
    for cert in certs {
        store_builder.add_cert(cert).unwrap();
    }
    store_builder.set_flags(X509VerifyFlags::NO_CHECK_TIME).expect("Set X509Store flag failed");
    store_builder.build()
}

fn verify_certs(cert: &X509, inter_ca:Vec<X509>, root_ca: Vec<X509>) -> Result<X509VerifyResult, ErrorStack>
{
    let cert_chain = convert_to_stack(inter_ca);
    let store = convert_to_store(root_ca);
    let mut ctx = X509StoreContext::new().expect("Create X509StoreContext failed");
    ctx.init(&store, cert, &cert_chain, |c| {
            c.verify_cert()?;
            Ok(c.error())
    })
}

/// get cert from file
/// verify the cert if a chain is found in file and then return the leaf cert in DER format
pub fn get_verifed_cert_from_chain(path: &str) -> Option<Vec<u8>>
{
    let mut certs = load_certs_from_pem_file(path).unwrap();
    let count = certs.len();
    match count {
        0 => {
            error!(LOG_LABEL, "No cert in file.");
            return None;
        },
        1 => {
            info!(LOG_LABEL, "Only one cert in file, use directly.");
            return dump_cert_in_der(certs.pop().unwrap());
        },
        _ => ()
    }
    // chain format: root_ca -> inter_ca(may 0, 1 or more) -> cert
    let cert = certs.pop().unwrap();
    let mut inter_ca = Vec::new();
    let mut root_ca = Vec::new();
    for _i in  1..count - 1 {
        inter_ca.push(certs.pop().unwrap());
    }
    root_ca.push(certs.pop().unwrap());
    match verify_certs(&cert, inter_ca, root_ca) {
        Ok(X509VerifyResult::OK) => (),
        Ok(result) => {
            error!(LOG_LABEL, "Verification failed: {}", @public(result.error_string()));
            return None;
        }
        Err(e) => {
            print_openssl_error_stack(e);
            return None;
        }
    }
    dump_cert_in_der(cert)
}