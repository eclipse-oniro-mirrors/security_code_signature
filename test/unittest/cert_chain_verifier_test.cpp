/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "access_token_setter.h"
#include "byte_buffer.h"
#include "cJSON.h"
#include "file_helper.h"
#include "huks_attest_verifier.h"
#include "log.h"

// Include the implementation to access static AddCAToStore and ATTEST_ROOT_CA_PATH.
// This test target is linked with "-Wl,--wrap=fopen" (see BUILD.gn): every fopen call
// in this binary resolves to WrapFopen below, which redirects rootcerts reads to a
// test-writable file when enabled, keeping the production source untouched.
static const char *ROOT_CERTS_REDIRECT_PATH = nullptr;
// must keep identical to ATTEST_ROOT_CA_PATH in the production source
static const char *const PROD_ROOT_CERTS_PATH = "/system/etc/security/oemdevcertca/rootcerts";

// The linker "--wrap" ABI mandates fixed assembler symbol names; the asm labels below
// bind them to style-compliant C++ identifiers, so no reserved identifier is declared
// or defined at source level while the emitted symbols stay exactly what the linker
// expects ("__wrap_fopen" defined here, "__real_fopen" resolved to the real fopen).
extern "C" FILE *RealFopen(const char *path, const char *mode) asm("__real_fopen");
extern "C" FILE *WrapFopen(const char *path, const char *mode) asm("__wrap_fopen");

extern "C" FILE *WrapFopen(const char *path, const char *mode)
{
    if ((ROOT_CERTS_REDIRECT_PATH != nullptr) && (path != nullptr) &&
        (strcmp(path, PROD_ROOT_CERTS_PATH) == 0)) {
        return RealFopen(ROOT_CERTS_REDIRECT_PATH, mode);
    }
    return RealFopen(path, mode);
}

#include "../../utils/src/huks_attest_verifier.cpp"

using namespace OHOS::Security::CodeSign;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace CodeSign {
const std::string SIGNING_CERT_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDgzCCAm2gAwIBAgIBATALBgkqhkiG9w0BAQswfzELMAkGA1UEBhMCQ04xEzAR\n" \
"BgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsM\n" \
"CmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29ybGQxMTExGTAXBgkqhkiG9w0B\n" \
"CQEWCmhlbGxvd29ybGQwHhcNMjQwODA5MDkzMDEyWhcNMzQwODA5MDkzMDEyWjAa\n" \
"MRgwFgYDVQQDEw9BIEtleW1hc3RlciBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMB\n" \
"BwNCAATJqTRIhGKhLmXuJbPI311/5gEljqPbpJpXNp6oe8dOmnyJ9SQQZmMomB5u\n" \
"lC5aZIoNrCuKHTAgY1PpNNcFSBBpo4IBPDCCATgwCwYDVR0PBAQDAgeAMAgGA1Ud\n" \
"HwQBADCCAR0GDCsGAQQBj1sCgngBAwSCAQswggEHAgEAMDQCAQAGDSsGAQQBj1sC\n" \
"gngCAQQEIOIC9EG2Dn3zqle0WWjiHwk2CIP3hJuPjjQwi7z4FaFFMCICAQIGDSsG\n" \
"AQQBj1sCgngCAQIEDkxPQ0FMX1NJR05fS0VZMFwCAQIGDSsGAQQBj1sCgngCAQMw\n" \
"SAYOKwYBBAGPWwKCeAIBAwEENnsicHJvY2Vzc05hbWUiOiJsb2NhbF9jb2RlX3Np\n" \
"Z24iLCJBUEwiOiJzeXN0ZW1fYmFzaWMifTAYAgECBg0rBgEEAY9bAoJ4AgELBAQA\n" \
"AAAAMBgCAQIGDSsGAQQBj1sCgngCAQUEBAIAAAAwFgIBAgYOKwYBBAGPWwKCeAIE\n" \
"AQUBAf8wCwYJKoZIhvcNAQELA4IBAQB8zqqeaXux3qkQF0GFax7I4YWtTpoeQeJU\n" \
"BjyMk/eGmeX+ZD9absOQDzH/wH6MddzPLjoaIuoR+oxDXn2yqQ5xyGQp6uN0E8IB\n" \
"OFCjeTbRBR86A+CulTGuitszOpfyKF7SvmzfGx+ij2OtQnZ7QZp+I2YEr1Jc4ESr\n" \
"xXXt0zPslidnf7qso+f09C6U9YOnaxISfjxEqFn25+yWX2tXBJ62L6R7+zpKU3ee\n" \
"0ljf4jYtlza7s5mYJ2+OHlwdXuF38cpS59cG48UpsL0DAqywqjs5uaGthkrWo2YB\n" \
"FlAL4bVfBj2FmcqNhz+j3dgLTNA3VczwkNbj/FIY1T+FDTqnsCED\n" \
"-----END CERTIFICATE-----";

const std::string ISSUER_CERT_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDyzCCArOgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJDTjET\n" \
"MBEGA1UECAwKaGVsbG93b3JsZDETMBEGA1UECgwKaGVsbG93b3JsZDETMBEGA1UE\n" \
"CwwKaGVsbG93b3JsZDEVMBMGA1UEAwwMaGVsbG93b3JsZDExMRkwFwYJKoZIhvcN\n" \
"AQkBFgpoZWxsb3dvcmxkMB4XDTIyMDEyMjA5MjUzM1oXDTMyMDEyMDA5MjUzM1ow\n" \
"fzELMAkGA1UEBhMCQ04xEzARBgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhl\n" \
"bGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29y\n" \
"bGQxMTExGTAXBgkqhkiG9w0BCQEWCmhlbGxvd29ybGQwggEiMA0GCSqGSIb3DQEB\n" \
"AQUAA4IBDwAwggEKAoIBAQC8HHhVEbY3uuriW3wAcAMFwIUd+VImAUKnWAYlsiHL\n" \
"Ps3BhpHHb67kjzP3rcQbZ2l1LSMWjoV8jXckVMOFqOlTlrYlGM3G80bVaWcEgw4c\n" \
"+nkSk+ApGmNUa69HK3h+5vfz81fVmJL1zX0VaYiA+wCzrFc1w5aGKhsFIcIY8FUo\n" \
"i15xrwAURQ+/EylzeF302qGwkCHYy4zQqn3ohku25rPLUOyOp6gJNs/3BVh76b9/\n" \
"1iTyP7ldDD7VV4UQCTDppFtrDQY/UrBhe9sPn0+6GWBfkkjz5n1aGE7JP2vmB3qM\n" \
"gxIpEkmVLVIxh6dwBOmtr+sT7xJ+UzmTWbbhNGCkzSPxAgMBAAGjUzBRMB0GA1Ud\n" \
"DgQWBBSDTqp6QOdxk9zF2H+7IGOckq/A1DAfBgNVHSMEGDAWgBRNYAEJlwxPOj5F\n" \
"B7M4mTsMpokRLzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB4\n" \
"CkKbJQWuC2pj0cS+zb4v8fRq8OPjRVPylqjHX4IMpmnl2VM0DkNXD0SYPC5IxkK4\n" \
"bgtglG0Rkr4blYf+PdNenbebWZvw4Y3JUoQgSasfdIA/rJXZtf3mVUNLmPlcRWZC\n" \
"OtGJmvlntp7/qWl7JCIaiD732baJU1DZchy3am2WWGpchBESBOtoSvdywG+T0xQQ\n" \
"cXzYQ+mHPsym30JCzChvZCKz+QJlIZUJ3XgoKH7MVviASXGcWLKOBYYUDt3J8/PM\n" \
"shbsqb+rm+VqU5ohV8Rr/nQ+QLvEFa8rrz7qY6/2QSbUy7QvFCv7MXFD1kCH92FL\n" \
"GwkmWDavM1kdVMXZmV54\n" \
"-----END CERTIFICATE-----";

const std::string INTER_CA_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIID3zCCAsegAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMCQ04x\n" \
"EzARBgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAcMCmhlbGxvd29ybGQxEzARBgNV\n" \
"BAoMCmhlbGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29ybGQxFDASBgNVBAMMC2hl\n" \
"bGxvd29ybGQxMRkwFwYJKoZIhvcNAQkBFgpoZWxsb3dvcmxkMB4XDTIyMDEyMjA5\n" \
"MjM0OFoXDTMyMDEyMDA5MjM0OFowfjELMAkGA1UEBhMCQ04xEzARBgNVBAgMCmhl\n" \
"bGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29y\n" \
"bGQxFTATBgNVBAMMDGhlbGxvd29ybGQxMTEZMBcGCSqGSIb3DQEJARYKaGVsbG93\n" \
"b3JsZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTJF+SAh/ccmcxF\n" \
"+le0m8Wx7N9kclMYoUVGyJOPDv0L9kE/1hg9HEavCBWal9ZK69r+i1YiH18Y0F5o\n" \
"AuqP0teedDByPii8IaDquJKZ1hlMi13vPY1cgUcG77cKzC5TMlmNTLes0ddn9/lY\n" \
"4ajl4kgUr3bCEXlp4uhBQPYlntujctcjmEdMtcJQmhHpr2Js9cq2kZney59ae5kk\n" \
"LCzpFqpj7cunz5Rs3RZs1+Njw5oABS18qAy1CEBnecLOi6lIPvIckngBHduwczOM\n" \
"5YBBXeqOeNk7FWTiIf5MuXlqOSlZ57Wp8SqfDzwS49awwI9dvGpjgyGh3ZQA5TXX\n" \
"GGIsn5cCAwEAAaNTMFEwHQYDVR0OBBYEFE1gAQmXDE86PkUHsziZOwymiREvMB8G\n" \
"A1UdIwQYMBaAFJp3c+VFpGlC/r/UiPCozoH1UcgMMA8GA1UdEwEB/wQFMAMBAf8w\n" \
"DQYJKoZIhvcNAQELBQADggEBAArLbWZWG3cHuCnMBGo28F0KVKctxjLVOCzDhKnH\n" \
"IusLVqTnZ7AHeUU56NyoRfSRSIEJ2TNXkHO8MyxNN3lP4RapQavOvENLE99s269I\n" \
"suLPCp3k6znJX1ZW7MIrSp7Bz+6rBTuh2H874H/BcvPXaCZB4X3Npjfu4tRcKEtS\n" \
"JKdVmIlotjX1qM5eYHY5BDSR0MvRYvSlH7/wA9FEGJ8GHI7vaHxIMxf4+OOz+E4w\n" \
"qKIZZfYeVBdEpZvfVGHRbS5dEofqc4NthlObTWlwAIhFgTzLqy8y2Y2jDWcJk91/\n" \
"y9u8F1jQAuoemDCY5BalZ+Bn0eZQQHlXujwyZfoIK+oCuUo=\n" \
"-----END CERTIFICATE-----";

const uint8_t CHALLENGE[] = {
    0xe2, 0x2, 0xf4, 0x41, 0xb6, 0xe, 0x7d, 0xf3,
    0xaa, 0x57, 0xb4, 0x59, 0x68, 0xe2, 0x1f, 0x9,
    0x36, 0x8, 0x83, 0xf7, 0x84, 0x9b, 0x8f, 0x8e,
    0x34, 0x30, 0x8b, 0xbc, 0xf8, 0x15, 0xa1, 0x45
};

const std::string READ_FILE_TEST_PATH = "/data/test/tmp/cert_chain_verifier_read_test.txt";
const char *const ROOT_CERTS_TEST_PATH = "/data/test/tmp/rootcerts";
constexpr uint32_t TEST_READ_FILE_MAX_SIZE = 12 * 1024;

// root of the fixture attestation chain (CN=helloworld1), serves as the
// test-provided trust anchor for the end-to-end verification case
const std::string ROOT_CA_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIIEBzCCAu+gAwIBAgIUSvxlT2cTI5rj67Ng5lqQ76peRYswDQYJKoZIhvcNAQEL\n" \
"BQAwgZIxCzAJBgNVBAYTAkNOMRMwEQYDVQQIDApoZWxsb3dvcmxkMRMwEQYDVQQH\n" \
"DApoZWxsb3dvcmxkMRMwEQYDVQQKDApoZWxsb3dvcmxkMRMwEQYDVQQLDApoZWxs\n" \
"b3dvcmxkMRQwEgYDVQQDDAtoZWxsb3dvcmxkMTEZMBcGCSqGSIb3DQEJARYKaGVs\n" \
"bG93b3JsZDAeFw0yMjAxMjIwOTIxNDRaFw0zMjAxMjAwOTIxNDRaMIGSMQswCQYD\n" \
"VQQGEwJDTjETMBEGA1UECAwKaGVsbG93b3JsZDETMBEGA1UEBwwKaGVsbG93b3Js\n" \
"ZDETMBEGA1UECgwKaGVsbG93b3JsZDETMBEGA1UECwwKaGVsbG93b3JsZDEUMBIG\n" \
"A1UEAwwLaGVsbG93b3JsZDExGTAXBgkqhkiG9w0BCQEWCmhlbGxvd29ybGQwggEi\n" \
"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnf9wv+5yjFTjR4iEFx792ROxA\n" \
"J3TCbALv68l+xAEbYLY8Uen3Zx9i55iwm6uJrEK3qhVyf3jDPBZA2XC8ta1TDG01\n" \
"i8BsVwl5l7EZXvtt0t0McP7AwHYQRr2r+oSHzyox9In+39uo0ZbUWVO8MoewubLD\n" \
"0TyYvmakol0/mkOWan3LU9BYrjayQHmwfIr9J4aGdfTrguVKrTcs/+eVJycOmC3v\n" \
"5kQg4taE0UxJw+sISyMcVcXgFW8qlcCtYIqwMvyi/ZEfE/DvHHtsRkGKEYkk4LAh\n" \
"hqtKqYZJK+hB1gAEZ/6Ox8ryoV9Q7H2LdkwBCrzhLFY8ZUlKyddXqpNyAnnHAgMB\n" \
"AAGjUzBRMB0GA1UdDgQWBBSad3PlRaRpQv6/1IjwqM6B9VHIDDAfBgNVHSMEGDAW\n" \
"gBSad3PlRaRpQv6/1IjwqM6B9VHIDDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" \
"DQEBCwUAA4IBAQA0G+qd52/lic6XrlpaZvAf1jI75fZARdAE0RM9SX1ouYF/AjNu\n" \
"8atrSQOyX4xz0Dz82CfCil/pazEiyagChSe249SRXxUXUD6v2yVuXjjGJdZjP3S4\n" \
"T6iMq34Zg4lNxaPD/dW5hHbIKX/NFwzMzp5guc+tgTLVZRILLvQ2VgO9E9ZC3fvJ\n" \
"5dBKnOHyRR8jE1b7wZ5Bm635FqoMI4GdJ9doqUketbWmuxFaNxNOl70oF4Nqai8u\n" \
"ogBCx/4P/K+IhGWiTwIT/alLtjHF+kHTS6aw4wxKr6oLj8U0nHfBNWUDLSsMS91p\n" \
"xuSX+C1JOt0mtwnTPe7FCSHNc0EFwfHbjjp/\n" \
"-----END CERTIFICATE-----";

static bool WriteFileContent(const std::string &path, const std::string &content)
{
    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }
    ofs << content;
    ofs.close();
    return true;
}

// subject of INTER_CA_CHAIN_PEM: CN=helloworld11, OU=helloworld, O=helloworld, C=CN
const std::string INTER_CA_MATCH_JSON =
    "{\"test\": {\"cn\": \"helloworld11\", \"ou\": \"helloworld\", \"o\": \"helloworld\", \"c\": \"CN\"}}";

// inject parsed JSON into the subject infos cache to make verification deterministic,
// works because the implementation is included in this translation unit
static bool InjectSubCaInfos(const std::string &json)
{
    cJSON *root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_subCaSubjectInfosMutex);
    if (g_subCaSubjectInfos != nullptr) {
        cJSON_Delete(g_subCaSubjectInfos);
    }
    g_subCaSubjectInfos = root;
    return true;
}

static void ResetSubCaInfosCache()
{
    std::lock_guard<std::mutex> lock(g_subCaSubjectInfosMutex);
    if (g_subCaSubjectInfos != nullptr) {
        cJSON_Delete(g_subCaSubjectInfos);
        g_subCaSubjectInfos = nullptr;
    }
}

static ByteBuffer g_issuerCert;
static ByteBuffer g_signingCert;
static ByteBuffer g_interCA;
static ByteBuffer g_invalidCert;
static ByteBuffer g_rootCA;

static inline uint8_t *CastToUint8Ptr(uint32_t *ptr)
{
    return reinterpret_cast<uint8_t *>(ptr);
}

static X509 *LoadPemString(const std::string &pemData)
{
    BIO *mem = BIO_new_mem_buf(pemData.c_str(), pemData.length());
    if (mem == nullptr) {
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(mem, nullptr, nullptr, nullptr);
    EXPECT_NE(x509, nullptr);
    BIO_free(mem);
    return x509;
}

void LoadDerFormPemString(const std::string &pemData, ByteBuffer &certBuffer)
{
    X509 *x509 = LoadPemString(pemData);
    uint8_t *derTemp = nullptr;
    int32_t derTempLen = i2d_X509(x509, &derTemp);
    EXPECT_NE(derTemp, nullptr);
    if (derTempLen < 0) {
        X509_free(x509);
        return;
    }

    certBuffer.CopyFrom(derTemp, static_cast<uint32_t>(derTempLen));

    X509_free(x509);
    OPENSSL_free(derTemp);
}

static void FormattedCertChain(const std::vector<ByteBuffer> &certChain, ByteBuffer &buffer)
{
    uint32_t certsCount = certChain.size();
    uint32_t totalLen = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        totalLen += sizeof(uint32_t) + certChain[i].GetSize();
    }
    buffer.Resize(totalLen);
    if (!buffer.PutData(0, CastToUint8Ptr(&certsCount), sizeof(uint32_t))) {
        return;
    }
    uint32_t pos = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        uint32_t size = certChain[i].GetSize();
        if (!buffer.PutData(pos, CastToUint8Ptr(&size), sizeof(uint32_t))) {
            return;
        }
        pos += sizeof(uint32_t);
        if (!buffer.PutData(pos, certChain[i].GetBuffer(), certChain[i].GetSize())) {
            return;
        }
        pos += certChain[i].GetSize();
    }
}

class CertChainVerifierTest : public testing::Test {
public:
    CertChainVerifierTest() {};
    virtual ~CertChainVerifierTest() {};
    static void SetUpTestCase()
    {
        LoadDerFormPemString(SIGNING_CERT_CHAIN_PEM, g_signingCert);
        LoadDerFormPemString(ISSUER_CERT_CHAIN_PEM, g_issuerCert);
        LoadDerFormPemString(INTER_CA_CHAIN_PEM, g_interCA);
        // fake root CA, no use in verifying
        uint8_t tmp = 0;
        g_rootCA.CopyFrom(&tmp, sizeof(tmp));
        g_invalidCert.CopyFrom(&tmp, sizeof(tmp));
    }
    static void TearDownTestCase()
    {
        ResetSubCaInfosCache();
    };
    void SetUp()
    {
        // every case starts with an empty subject infos cache
        ResetSubCaInfosCache();
    };
    void TearDown()
    {
        // never leak the fopen redirection into other cases
        ROOT_CERTS_REDIRECT_PATH = nullptr;
    };
};

/**
 * @tc.name: CertChainVerifierTest_001
 * @tc.desc: Get chain from empty buffer
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_001, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0002
 * @tc.desc: Get chain from empty cert chain
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_002, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    uint32_t count = 0;
    cert.CopyFrom(reinterpret_cast<uint8_t *>(&count), sizeof(count));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}


/**
 * @tc.name: CertChainVerifierTest_0003
 * @tc.desc: Get chain from invalid formatted buffer
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_003, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    std::vector<uint32_t> tmpBuffer = {0};
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // one cert in cert chain, classify as root CA
    tmpBuffer[0] = 1;
    // load issuer failed
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // two certs in cert chain
    tmpBuffer[0] = 2;
    // cert size
    tmpBuffer.push_back(sizeof(uint32_t));
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    // no content to load cert, convert from formatted buffer failed
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // fill issuer
    tmpBuffer.push_back(0);
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    // invalid content, convert content to x509 failed
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0004
 * @tc.desc: Get verified failed with invalid issuer format
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_004, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_invalidCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0005
 * @tc.desc: Get verified failed with invalid interCA format
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_005, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_issuerCert);
    certs.push_back(g_invalidCert);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0006
 * @tc.desc: verifying issuer cert failed
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_006, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_signingCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0007
 * @tc.desc: verify signing cert failed
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_007, TestSize.Level0)
{
    ByteBuffer challenge;
    //parse pub key of failed
    EXPECT_EQ(VerifyCertAndExtension(nullptr, nullptr, challenge), false);
    
    X509 *signingCert = LoadPemString(SIGNING_CERT_CHAIN_PEM);
    X509 *issuerCert = LoadPemString(ISSUER_CERT_CHAIN_PEM);
    // verify signature failed
    EXPECT_EQ(VerifyCertAndExtension(issuerCert, signingCert, challenge), false);

    // verify extension failed
    const char *invalidChallenge = "invalid";
    challenge.CopyFrom(reinterpret_cast<const uint8_t *>(invalidChallenge),
        sizeof(invalidChallenge));
    EXPECT_EQ(VerifyCertAndExtension(signingCert, issuerCert, challenge), false);

    // verify extension success
    challenge.CopyFrom(CHALLENGE, sizeof(CHALLENGE));
    EXPECT_EQ(VerifyCertAndExtension(signingCert, issuerCert, challenge), true);
    X509_free(signingCert);
    X509_free(issuerCert);
}

/**
 * @tc.name: CertChainVerifierTest_0008
 * @tc.desc: verifying issuer cert success
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_008, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_issuerCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    // preset matching subject infos so the intermediate CA subject check is deterministic
    ASSERT_TRUE(InjectSubCaInfos(INTER_CA_MATCH_JSON));
    // verify extension success
    challenge.CopyFrom(CHALLENGE, sizeof(CHALLENGE));
#ifdef CODE_SIGNATURE_OH_ROOT_CA
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), true);
#else
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
#endif
}

/**
 * @tc.name: CertChainVerifierTest_009
 * @tc.desc: ReadFileToString open nonexistent file failed
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_009, TestSize.Level0)
{
    // make sure the file does not exist
    (void) remove(READ_FILE_TEST_PATH.c_str());
    std::string content = "preset";
    EXPECT_EQ(ReadFileToString(READ_FILE_TEST_PATH, TEST_READ_FILE_MAX_SIZE, content), false);
}

/**
 * @tc.name: CertChainVerifierTest_010
 * @tc.desc: ReadFileToString read file content success
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_010, TestSize.Level0)
{
    const std::string expected = "{\"cn\": \"test\"}\nsecond line";
    {
        std::ofstream ofs(READ_FILE_TEST_PATH, std::ios::out | std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(ofs.is_open());
        ofs << expected;
        ofs.close();
    }
    std::string content;
    EXPECT_EQ(ReadFileToString(READ_FILE_TEST_PATH, TEST_READ_FILE_MAX_SIZE, content), true);
    EXPECT_EQ(content, expected);

    // empty file: read success with empty content
    {
        std::ofstream ofs(READ_FILE_TEST_PATH, std::ios::out | std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(ofs.is_open());
        ofs.close();
    }
    content = "preset";
    EXPECT_EQ(ReadFileToString(READ_FILE_TEST_PATH, TEST_READ_FILE_MAX_SIZE, content), true);
    EXPECT_TRUE(content.empty());

    (void) remove(READ_FILE_TEST_PATH.c_str());
}

/**
 * @tc.name: CertChainVerifierTest_011
 * @tc.desc: AddCAToStore with the deployed rootcerts on device
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_011, TestSize.Level0)
{
    X509_STORE *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    struct stat fileStat = {};
    bool fileExists = (stat(ATTEST_ROOT_CA_PATH.c_str(), &fileStat) == 0);
    bool ret = AddCAToStore(store);
    int certCount = sk_X509_OBJECT_num(X509_STORE_get0_objects(store));
    if (fileExists && (fileStat.st_size > 0)) {
        // deployed rootcerts must be readable and contain at least one root CA
        EXPECT_EQ(ret, true);
        EXPECT_GT(certCount, 0);
    } else {
        // file missing or empty: no trusted root may be loaded
        EXPECT_EQ(ret, false);
        EXPECT_EQ(certCount, 0);
    }
    X509_STORE_free(store);
}

/**
 * @tc.name: CertChainVerifierTest_012
 * @tc.desc: AddCAToStore repeated load keeps store consistent
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_012, TestSize.Level0)
{
    X509_STORE *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    bool firstRet = AddCAToStore(store);
    int firstCount = sk_X509_OBJECT_num(X509_STORE_get0_objects(store));
    // load again: duplicate certs are rejected with error log, call itself still succeeds
    bool secondRet = AddCAToStore(store);
    int secondCount = sk_X509_OBJECT_num(X509_STORE_get0_objects(store));
    EXPECT_EQ(secondRet, firstRet);
    EXPECT_EQ(secondCount, firstCount);
    X509_STORE_free(store);
}

/**
 * @tc.name: CertChainVerifierTest_013
 * @tc.desc: VerifyIntermediateCASubject with injected subject infos
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_013, TestSize.Level0)
{
    std::vector<ByteBuffer> chain { g_interCA };

    // empty chain is rejected before any loading
    std::vector<ByteBuffer> emptyChain;
    EXPECT_EQ(VerifyIntermediateCASubject(emptyChain), false);

    // entry fully matching cn/ou/o/c passes
    ASSERT_TRUE(InjectSubCaInfos(INTER_CA_MATCH_JSON));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), true);

    // common name mismatched
    ResetSubCaInfosCache();
    ASSERT_TRUE(InjectSubCaInfos("{\"entry\": {\"cn\": \"not-exist-ca\", \"c\": \"CN\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), false);
}

/**
 * @tc.name: CertChainVerifierTest_014
 * @tc.desc: only common name is compared, other fields are ignored
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_014, TestSize.Level0)
{
    std::vector<ByteBuffer> chain { g_interCA };

    // only cn constrained, matched
    ASSERT_TRUE(InjectSubCaInfos("{\"entry\": {\"cn\": \"helloworld11\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), true);

    // cn matched, ou/o/c mismatched but not constrained anymore
    ResetSubCaInfosCache();
    ASSERT_TRUE(InjectSubCaInfos(
        "{\"entry\": {\"cn\": \"helloworld11\", \"ou\": \"mismatch-ou\","
        " \"o\": \"mismatch-o\", \"c\": \"XX\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), true);

    // cn mismatched even if other fields all match
    ResetSubCaInfosCache();
    ASSERT_TRUE(InjectSubCaInfos(
        "{\"entry\": {\"cn\": \"not-exist-ca\", \"ou\": \"helloworld\","
        " \"o\": \"helloworld\", \"c\": \"CN\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), false);
}

/**
 * @tc.name: CertChainVerifierTest_015
 * @tc.desc: invalid entries are skipped or rejected
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_015, TestSize.Level0)
{
    std::vector<ByteBuffer> chain { g_interCA };

    // entry without mandatory cn is skipped
    ASSERT_TRUE(InjectSubCaInfos("{\"entry\": {\"ou\": \"helloworld\", \"o\": \"helloworld\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), false);

    // cn with non-string type is rejected
    ResetSubCaInfosCache();
    ASSERT_TRUE(InjectSubCaInfos("{\"entry\": {\"cn\": 12345}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), false);

    // multiple entries: non-object entry skipped, any matching entry passes
    ResetSubCaInfosCache();
    ASSERT_TRUE(InjectSubCaInfos(
        "{\"测试条目\": {\"cn\": \"not-exist-ca\"},"
        " \"bad\": 123,"
        " \"test\": {\"cn\": \"helloworld11\", \"o\": \"helloworld\"}}"));
    EXPECT_EQ(VerifyIntermediateCASubject(chain), true);
}

/**
 * @tc.name: CertChainVerifierTest_016
 * @tc.desc: LoadSubCaSubjectInfosLocked with the deployed subcasubjectinfos
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_016, TestSize.Level0)
{
    ResetSubCaInfosCache();
    struct stat fileStat = {};
    bool fileValid = (stat(SUB_CA_SUBJECT_INFOS_PATH.c_str(), &fileStat) == 0) &&
        (fileStat.st_size > 0);
    bool loaded;
    {
        std::lock_guard<std::mutex> lock(g_subCaSubjectInfosMutex);
        loaded = LoadSubCaSubjectInfosLocked();
    }
    if (fileValid) {
        // deployed subcasubjectinfos must be a valid JSON object and cached after load
        EXPECT_EQ(loaded, true);
        EXPECT_NE(g_subCaSubjectInfos, nullptr);
    } else {
        // file missing or empty: load fails and subject verification is rejected
        EXPECT_EQ(loaded, false);
        EXPECT_EQ(g_subCaSubjectInfos, nullptr);
        std::vector<ByteBuffer> chain { g_interCA };
        EXPECT_EQ(VerifyIntermediateCASubject(chain), false);
    }
    ResetSubCaInfosCache();
}

/**
 * @tc.name: CertChainVerifierTest_017
 * @tc.desc: end-to-end verification with mocked HUKS attestation chain and test-provided root
 * @tc.type: FUNC
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_017, TestSize.Level0)
{
    // put the root of the fixture attestation chain into the test file,
    // then redirect AddCAToStore's fopen to it
    ASSERT_TRUE(WriteFileContent(ROOT_CERTS_TEST_PATH, ROOT_CA_PEM));
    ROOT_CERTS_REDIRECT_PATH = ROOT_CERTS_TEST_PATH;

    // subject whitelist entry matching the intermediate CA common name
    ASSERT_TRUE(InjectSubCaInfos(INTER_CA_MATCH_JSON));

    // mocked HUKS key attestation output: formatted chain of
    // signing cert (with challenge extension) + issuer + intermediate CA + root
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs { g_signingCert, g_issuerCert, g_interCA, g_rootCA };
    FormattedCertChain(certs, formattedCert);
    challenge.CopyFrom(CHALLENGE, sizeof(CHALLENGE));

    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), true);

    // output cert must be the DER of the signing cert
    ASSERT_EQ(certBuffer.GetSize(), g_signingCert.GetSize());
    EXPECT_EQ(memcmp(certBuffer.GetBuffer(), g_signingCert.GetBuffer(), certBuffer.GetSize()), 0);

    ROOT_CERTS_REDIRECT_PATH = nullptr;
    (void) remove(ROOT_CERTS_TEST_PATH);
}

} // namespace CodeSign
} // namespace Security
} // namespace OHOS