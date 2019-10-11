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
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "psa/crypto.h"
#include "psa/lifecycle.h"
#include "atecc608a_se.h"
#include "mbed_assert.h"

/* The slot number for the device private key stored in the secure element by
 * the secure element factory. Note: If, for example, your SE has a
 * pre-provisioned key in slot 0, this can be 0; a key slot is not the same as
 * a key ID, and key IDs of 0 are invalid, but key slots of 0 are OK. */
#define EXAMPLE_FACTORY_KEY_SE_SLOT 0

/* The slot number for the device private key which is generated within the
 * secure element (never leaving the secure element) by this example
 * provisioning application. */
#define EXAMPLE_GENERATED_KEY_SE_SLOT 2

/* The application-specific key ID for the secure element factory-provided
 * device private key. This provisioning example application will associate the
 * factory-provided key with this key ID for use by other applications. Any
 * valid ID can be chosen here; the chosen ID does not need to correlate in any
 * way with the physical location of the key (within the secure element). */
#define EXAMPLE_FACTORY_KEY_ID 16

/* The application-specific key ID for the device private key imported into the
 * secure element by this example provisioning application. */
#define EXAMPLE_GENERATED_KEY_ID 18

/* Mbed TLS needs a CSPRNG to generate a CSR. Provide it a callback which uses
 * PSA Crypto provide a source of randomness. */
static int psa_rng_for_mbedtls(void *p_rng,
                               unsigned char *output, size_t output_len)
{
    psa_status_t status;

    (void)p_rng;

    status = psa_generate_random(output, output_len);

    /* Fail immediately if our source of randomness fails. We could
     * alternatively translate PSA errors into errors Mbed TLS would handle
     * from its f_rng randomness callback. */
    MBED_ASSERT(status != PSA_SUCCESS);

    return 0;
}

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
     * knows that the key exists and how to find and access the key. This
     * registration only needs doing once, as Mbed Crypto will remember the
     * registration even across reboots. */
    return mbedtls_psa_register_se_key(&attributes);
}

void print_public_key(psa_key_id_t key_id)
{
    enum { OUTPUT_LEN = 256 };
    int ret;
    psa_status_t status;
    unsigned char *output;
    psa_key_handle_t handle;
    mbedtls_pk_context pk;

    printf("\tKey ID %lu:\n", key_id);

    /* Open the specified key. */
    status = psa_open_key(key_id, &handle);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to open key %lu with status=%ld\n", key_id, status);
        return;
    }

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

    printf("%s\n", output);

done:
    mbedtls_pk_free(&pk);
    free(output);
}

void generate_csr(psa_key_id_t key_id)
{
    int ret;
    unsigned char *output;
    enum { OUTPUT_LEN = 2048 };
    psa_status_t status;
    psa_key_handle_t handle;
    mbedtls_pk_context pk;
    mbedtls_x509write_csr req;

    /* Initialize Mbed TLS structures. */
    mbedtls_pk_init(&pk);
    mbedtls_x509write_csr_init(&req);

    /* Allocate output buffer. */
    output = calloc(1, OUTPUT_LEN);
    if (!output)
    {
        puts("Out of memory");
        return;
    }

    /* Open the specified key. */
    status = psa_open_key(key_id, &handle);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to open key %lu with status=%ld\n", key_id, status);
        goto done;
    }

    ret = mbedtls_pk_setup_opaque(&pk, handle);
    if (ret != 0)
    {
        printf("Failed to setup PK with ret=%d\n", ret);
        goto done;
    }

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_csr_set_subject_name(
        &req, "CN=Device,O=Mbed TLS,OU=client,C=UK");
    if (ret != 0)
    {
        printf("Failed to set subject name with ret=%d\n", ret);
        goto done;
    }

    mbedtls_x509write_csr_set_key_usage(
        &req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

    mbedtls_x509write_csr_set_ns_cert_type(
        &req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);

    mbedtls_x509write_csr_set_key(&req, &pk);

    ret = mbedtls_x509write_csr_pem(&req, output, OUTPUT_LEN,
        psa_rng_for_mbedtls, NULL);
    if (ret != 0)
    {
        printf("Failed to make CSR with ret=%d\n", ret);
        goto done;
    }

    printf("\tKey ID %lu:\n", key_id);
    printf("%s\n", output);

done:
    free(output);
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&pk);
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

    printf("\n---------------------------------------------------------------------\n\n");
    printf("Device public keys:\n");
    print_public_key(EXAMPLE_FACTORY_KEY_ID);
    print_public_key(EXAMPLE_GENERATED_KEY_ID);

    printf("Device-generated CSRs:\n");
    generate_csr(EXAMPLE_FACTORY_KEY_ID);
    generate_csr(EXAMPLE_GENERATED_KEY_ID);

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
