/*
 * Copyright (c) 2019, Arm Limited and affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
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

#include <stdio.h>
#include <stdlib.h>

#if defined(ATCA_HAL_I2C)
#include "mbedtls/pk.h"
#include "psa/crypto.h"
#include "psa/lifecycle.h"
#include "atecc608a_se.h"

/* The slot number for the device private key stored in the secure element by
 * the secure element factory. Note: If, for example, your SE has a
 * pre-provisioned key in slot 0, this can be 0; a key slot is not the same as
 * a key ID, and key IDs of 0 are invalid, but key slots of 0 are OK. */
#define EXAMPLE_FACTORY_KEY_SE_SLOT 0

/* The slot number for the device private key which is imported into the secure
 * element by this example provisioning application. */
#define EXAMPLE_IMPORTED_KEY_SE_SLOT 1

/* The slot number for the device private key which is generated within the
 * secure element (never leaving the secure element) by this example
 * provisioning application. */
#define EXAMPLE_GENERATED_KEY_SE_SLOT 2

/* The application-specific key ID for the secure element factory-provided
 * device private key. This provisioning example application will associate the
 * factory-provided key with this key ID for use by other applications. Any
 * valid ID can be chosen here; the chosen ID does not need to correlate in any
 * way with the physical location of the key (within the secure element). */
#define EXAMPLE_FACTORY_KEY_ID 0x10

/* The application-specific key ID for the device private key imported into the
 * secure element by this example provisioning application. */
#define EXAMPLE_IMPORTED_KEY_ID 0x11

/* The application-specific key ID for the device private key imported into the
 * secure element by this example provisioning application. */
#define EXAMPLE_GENERATED_KEY_ID 0x12

#if 0
/* XXX Currently, we don't have any SE that supports importing keys. */
psa_status_t import_pregenerated_keys(void)
{
    static const uint8_t key[] = {
        0xFB, 0xFF, 0x17, 0xD5, 0x4C, 0x45, 0x15, 0xCD,
        0x26, 0xBB, 0x65, 0xFE, 0xB3, 0xF7, 0xEF, 0x67,
        0xEC, 0x7D, 0x0A, 0x62, 0x62, 0x15, 0xBD, 0x48,
        0xCB, 0xF1, 0xCE, 0x7E, 0xF6, 0x96, 0x8A, 0x03
    };

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    /* Set device private key attributes. */
    /* Note: It is not necessary to hard-code the physical slot number within
     * the secure element. The secure element driver can automatically allocate
     * a slot that fits your use case. */
    psa_set_key_slot_number(&attributes, EXAMPLE_IMPORTED_KEY_SE_SLOT);
    psa_set_key_id(&attributes, EXAMPLE_IMPORTED_KEY_ID);
    psa_set_key_lifetime(&attributes, PSA_ATECC608A_LIFETIME);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));

    /* Import the pre-generated key into the secure element. */
    status = psa_import_key(&attributes, key, sizeof(key), &handle);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_close_key(handle);
}
#endif

psa_status_t generate_key_on_device(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    /* Set device private key attributes. */
    /* Note: It is not necessary to hard-code the physical slot number within
     * the secure element. The secure element driver can automatically allocate
     * a slot that fits your use case. */
    psa_set_key_slot_number(&attributes, EXAMPLE_GENERATED_KEY_SE_SLOT);
    psa_set_key_id(&attributes, EXAMPLE_GENERATED_KEY_ID);
    psa_set_key_lifetime(&attributes, PSA_ATECC608A_LIFETIME);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));

    /* Generate the key inside the secure element. */
    status = psa_generate_key(&attributes, &handle);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_close_key(handle);
}

psa_status_t register_preprovisioned_keys(void)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* Set device private key attributes. */
    psa_set_key_slot_number(&attributes, EXAMPLE_FACTORY_KEY_SE_SLOT);
    psa_set_key_id(&attributes, EXAMPLE_FACTORY_KEY_ID);
    psa_set_key_lifetime(&attributes, PSA_ATECC608A_LIFETIME);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));

    /* Register the factory-created key with Mbed Crypto, so that Mbed Crypto
     * knows that the key exists and how to find and access the key. */
    return mbedtls_psa_register_se_key(&attributes);
}

void print_public_key_data(psa_key_handle_t handle)
{
    int ret;
    unsigned char *output;
    enum { OUTPUT_LEN = 256 };
    mbedtls_pk_context pk;

    output = calloc(1, OUTPUT_LEN);
    if (!output) {
        puts("Out of memory");
        return;
    }

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_setup_opaque(&pk, handle);
    if (ret != 0)
    {
        printf("Failed to setup PK with ret=%d\n", ret);
        goto done;
    }

    ret = mbedtls_pk_write_pubkey_pem(&pk, output, OUTPUT_LEN);
    if (ret != 0) {
        printf("Failed to print pubkey with ret=%d\n", ret);
        goto done;
    }

    printf("%s", output);

done:
    mbedtls_pk_free(&pk);
    free(output);
}

void print_public_key(psa_key_id_t key_id)
{
    psa_status_t status;
    psa_key_handle_t handle;

    putchar('\t');

    /* Open the specified key. */
    status = psa_open_key(key_id, &handle);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to open key %lu with status=%ld\n", key_id, status);
        return;
    }

    print_public_key_data(handle);
}

/* The secure element factory put a device private key pair (not attestation
 * key) into a slot in the secure element. We need to tell Mbed Crypto that
 * this key pair exists so that it can be used. */

/* Put trusted root CA certificate into persistent storage */
/* When and how should PSA use this? TLS wants for authenticating the server. */
/* Application will have this, not provisioning. */

int main(void)
{
    psa_status_t status;
    printf("Provisioning device...\n");

    printf("\tErasing device... ");
    fflush(stdout);
    status = mbed_psa_reboot_and_request_new_security_state(PSA_LIFECYCLE_ASSEMBLY_AND_TEST);
    if (status != PSA_SUCCESS)
    {
        printf("failed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

    printf("\tRegistering drivers... ");
    fflush(stdout);
    status = psa_register_se_driver(PSA_ATECC608A_LIFETIME, &atecc608a_drv_info);
    if (status != PSA_SUCCESS)
    {
        printf("failed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

    printf("\tInitializing PSA Crypto... ");
    fflush(stdout);
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("failed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

    printf("\tRegistering factory-created keys... ");
    fflush(stdout);
    status = register_preprovisioned_keys();
    if (status != PSA_SUCCESS)
    {
        printf("failed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

#if 0
    printf("\tImporting pre-generated keys into the secure element... ");
    fflush(stdout);
    status = import_pregenerated_keys();
    if (status != PSA_SUCCESS)
    {
        printf("\n\t\tfailed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");
#endif

    printf("\tGenerating keys within the secure element... ");
    fflush(stdout);
    status = generate_key_on_device();
    if (status != PSA_SUCCESS)
    {
        printf("\n\t\tfailed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

    printf("Device provisioned\n");

    printf("Device public keys:\n");
    print_public_key(EXAMPLE_FACTORY_KEY_ID);
    print_public_key(EXAMPLE_IMPORTED_KEY_ID);
    print_public_key(EXAMPLE_GENERATED_KEY_ID);

    return PSA_SUCCESS;
}
#else
int main(void)
{
    printf("Not all of the required options are defined:\n"
           "  - ATCA_HAL_I2C\n");
    return 0;
}
#endif
