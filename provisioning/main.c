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
#include "psa/crypto.h"
#include "psa/lifecycle.h"
#include "atecc608a_se.h"

/* The slot number for the device private key stored in the secure element by
 * the secure element factory. Note: If your SE has a pre-provisioned key in
 * slot 0, this can be 0; a key slot is not the same as a key ID, and key IDs
 * of 0 are invalid, but key slots of 0 are OK. */
#define EXAMPLE_DEVICE_KEY_SE_SLOT 1

/* The application-specific key ID for the device private key. */
#define EXAMPLE_DEVICE_KEY_ID 3

psa_status_t register_preprovisioned_keys(void)
{
    psa_key_attributes_t device_key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* Set device private key attributes. */
    psa_set_key_slot_number(&device_key_attributes,
                            EXAMPLE_DEVICE_KEY_SE_SLOT);
    psa_set_key_id(&device_key_attributes, EXAMPLE_DEVICE_KEY_ID);
    psa_set_key_lifetime(&device_key_attributes, PSA_ATECC608A_LIFETIME);
    psa_set_key_algorithm(&device_key_attributes,
                          PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_bits(&device_key_attributes, 256);
    psa_set_key_usage_flags(&device_key_attributes, PSA_KEY_USAGE_SIGN);
    psa_set_key_type(&device_key_attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));

    /* Register the factory-created key with Mbed Crypto. */
    return mbedtls_psa_register_se_key(&device_key_attributes);
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

    printf("Device provisioned\n");
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
