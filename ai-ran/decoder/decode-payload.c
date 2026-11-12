/* Offline inspection using the exact ASN.1 definitions of the pinned runtime. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aper_decoder.h"
#include "xer_encoder.h"

#ifdef AI_RAN_RC
#include "E2SM-RC-ControlMessage.h"
#define DESCRIPTOR asn_DEF_E2SM_RC_ControlMessage
#define DECODE aper_decode_complete
#define PRINT xer_fprint
#else
#include "E2AP-PDU.h"
#define DESCRIPTOR asn_DEF_E2AP_PDU_e2ap_v2_03
#define DECODE aper_decode_e2ap_v2_03_complete
#define PRINT xer_fprint_e2ap_v2_03
#endif

int main(void)
{
    const size_t capacity = 1024 * 1024;
    uint8_t* bytes = malloc(capacity);
    if (bytes == NULL) return 2;
    size_t length = fread(bytes, 1, capacity, stdin);
    if (length == 0 || ferror(stdin) || fgetc(stdin) != EOF) {
        fprintf(stderr, "Expected one nonempty ASN.1 message, at most 1 MiB\n");
        free(bytes);
        return 2;
    }
    void* pdu = NULL;
    asn_dec_rval_t result = DECODE(NULL, &DESCRIPTOR, &pdu, bytes, length);
    free(bytes);
    if (result.code != RC_OK) {
        fprintf(stderr, "ASN.1 decode failed (code %d, consumed %zu)\n", result.code, result.consumed);
        if (pdu != NULL) ASN_STRUCT_FREE(DESCRIPTOR, pdu);
        return 3;
    }
    int status = PRINT(stdout, &DESCRIPTOR, pdu);
    ASN_STRUCT_FREE(DESCRIPTOR, pdu);
    return status == 0 ? 0 : 4;
}
