#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    CK_RV rv = pkcs11h_initialize();
    if (rv != CKR_OK) {
        return -1;
    }
    pkcs11h_setLogLevel(PKCS11H_LOG_ERROR);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {
    if (s == 0 || s > 8092) {
        return 0;
    }
    std::vector<char> serialized_input(d, d + s);
    serialized_input.push_back('\0');  // null-terminate

    pkcs11h_certificate_id_t certificate_id = NULL;
    pkcs11h_certificate_deserializeCertificateId(&certificate_id, serialized_input.data());
    return 0;
}


