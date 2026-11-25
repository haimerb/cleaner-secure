#include "trust.h"

#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

#ifndef CERT_FIND_ISSUER_CERT
#define CERT_FIND_ISSUER_CERT 0x00020000u
#endif

#define CC_SHA256_CHUNK 1048576u

static void cc_hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

bool cc_hash_sha256_file(const wchar_t *path, char out[65])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    unsigned char *buffer = NULL;
    unsigned char digest[32];
    bool ok = false;

    if (path == NULL || out == NULL) {
        return false;
    }
    buffer = (unsigned char *)malloc(CC_SHA256_CHUNK);
    if (buffer == NULL) {
        return false;
    }
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        goto done;
    }
    if (!NT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0))) {
        goto done;
    }
    file = CreateFileW(path, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto done;
    }
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file, buffer, (DWORD)CC_SHA256_CHUNK, &read, NULL)) {
            goto done;
        }
        if (read == 0) {
            break;
        }
        if (!NT_SUCCESS(BCryptHashData(hash, buffer, read, 0))) {
            goto done;
        }
    }
    if (!NT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
        goto done;
    }
    cc_hex_encode(digest, sizeof(digest), out);
    ok = true;

done:
    free(buffer);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

static void cc_read_publisher(const wchar_t *path, wchar_t *publisher, DWORD count)
{
    HCERTSTORE store = NULL;
    HCRYPTMSG msg = NULL;
    PCMSG_SIGNER_INFO signer = NULL;
    PCCERT_CONTEXT cert = NULL;
    DWORD size = 0;
    DWORD encoding = 0;
    DWORD flags = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD used = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          &encoding, NULL, NULL, &store, &msg, NULL)) {
        goto done;
    }
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size) || size == 0) {
        goto done;
    }
    signer = (PCMSG_SIGNER_INFO)malloc(size);
    if (signer == NULL) {
        goto done;
    }
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer, &size)) {
        goto done;
    }
    {
        CERT_INFO info;
        memset(&info, 0, sizeof(info));
        info.SerialNumber = signer->SerialNumber;
        info.Issuer = signer->Issuer;
        cert = CertFindCertificateInStore(store, flags, 0, CERT_FIND_ISSUER_CERT,
                                          &info, NULL);
        if (cert != NULL) {
            CERT_INFO subject;
            memset(&subject, 0, sizeof(subject));
            subject.Subject = cert->pCertInfo->Subject;
            subject.SerialNumber = cert->pCertInfo->SerialNumber;
            CertFreeCertificateContext(cert);
            cert = NULL;
            cert = CertFindCertificateInStore(store, flags, 0, CERT_FIND_SUBJECT_CERT,
                                              &subject, NULL);
        }
    }
    if (cert != NULL) {
        used = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                                  publisher, count);
        if (used <= 1) {
            publisher[0] = L'\0';
        }
    }

done:
    if (cert != NULL) {
        CertFreeCertificateContext(cert);
    }
    free(signer);
    if (msg != NULL) {
        CryptMsgClose(msg);
    }
    if (store != NULL) {
        CertCloseStore(store, 0);
    }
}

bool cc_trust_verify(const wchar_t *path, cc_trust_result_t *out)
{
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO file_info;
    WINTRUST_DATA data;
    LONG status;
    bool verified = false;

    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->virustotal_hits = -1;
    out->virustotal_total = -1;
    out->publisher_checked = true;
    if (path == NULL) {
        return false;
    }
    (void)cc_hash_sha256_file(path, out->hash_sha256);

    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path;

    memset(&data, 0, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwUIContext = WTD_UICONTEXT_EXECUTE;
    data.pFile = &file_info;

    status = WinVerifyTrust(NULL, &action, &data);
    if (status == ERROR_SUCCESS) {
        verified = true;
        out->signature_valid = true;
        cc_read_publisher(path, out->publisher, CC_MAX_PUBLISHER);
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(NULL, &action, &data);
    return verified;
}

bool cc_is_elevated(void)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size = 0;
    bool elevated = false;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    memset(&elevation, 0, sizeof(elevation));
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
        size >= sizeof(elevation)) {
        elevated = elevation.TokenIsElevated != 0;
    }
    CloseHandle(token);
    return elevated;
}
