/*
 * Copyright (c) 2018, Arm Limited and affiliates
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

#include "psa/crypto.h"

#include <stdio.h>

#if defined(ATCA_HAL_I2C)

#define ASSERT_STATUS(actual, expected)                             \
    do                                                              \
    {                                                               \
        if ((actual) != (expected))                                 \
        {                                                           \
            printf("assertion failed at %s:%d "                     \
                   "(actual=%d expected=%d)\n", __FILE__, __LINE__, \
                   (int)actual, (int)expected);                     \
            return -1;                                                 \
        }                                                           \
    } while(0)

#include <inttypes.h>
#include <string.h>
#include "atca_status.h"
#include "atca_devtypes.h"
#include "atca_iface.h"
#include "atca_command.h"
#include "atca_basic.h"
#include "atca_helpers.h"

static ATCAIfaceCfg atca_iface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608A,
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 2,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20,
};

static const uint8_t hash_input1[] = "abc";
/* SHA-256 hash of ['a','b','c'] */
static const uint8_t sha256_expected_hash1[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static const uint8_t hash_input2[] = "";
/* SHA-256 hash of an empty string */
static const uint8_t sha256_expected_hash2[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,  0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static int hash_sha256(const uint8_t *input, size_t input_size,
                        const uint8_t *expected_hash, size_t expected_hash_size)
{
    uint8_t actual_hash[ATCA_SHA_DIGEST_SIZE] = {0};
    printf("SHA-256:\n\n");
    atcab_printbin_label("Input: ", (uint8_t *)input, input_size);
    atcab_printbin_label("Expected Hash: ", (uint8_t *)expected_hash, expected_hash_size);
    ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_hw_sha2_256(input, input_size, actual_hash), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
    atcab_printbin_label("Actual Hash: ", actual_hash, ATCA_SHA_DIGEST_SIZE);
    ASSERT_STATUS(memcmp(actual_hash, expected_hash, sizeof(actual_hash)), 0);
    printf("Success!\n\n");

    return 0;
}

static int read_serial_number(void)
{
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_read_serial_number(serial), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
    printf("Serial Number:\n");
    atcab_printbin_sp(serial, ATCA_SERIAL_NUM_SIZE);
    printf("\n");

    return 0;
}

static void hexdump(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i)
    {
        if (i != 0 && (i % 8 == 0))
        {
            printf(" ");
        }
        if (i != 0 && (i % 16 == 0))
        {
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}


#define PSA_ATECC608A_LIFETIME 0xdeadbeefU

static int inited = 0;

static psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret)
{
    switch (ret)
    {
    case ATCA_SUCCESS:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_WAKE_SUCCESS:
        return PSA_SUCCESS;
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_ID:
    case ATCA_INVALID_SIZE:
    case ATCA_SMALL_BUFFER:
    case ATCA_BAD_OPCODE:
    case ATCA_ASSERT_FAILURE:
        return PSA_ERROR_INVALID_ARGUMENT;
    case ATCA_RX_CRC_ERROR:
    case ATCA_RX_FAIL:
    case ATCA_STATUS_CRC:
    case ATCA_RESYNC_WITH_WAKEUP:
    case ATCA_PARITY_ERROR:
    case ATCA_TX_TIMEOUT:
    case ATCA_RX_TIMEOUT:
    case ATCA_TOO_MANY_COMM_RETRIES:
    case ATCA_COMM_FAIL:
    case ATCA_TIMEOUT:
    case ATCA_TX_FAIL:
    case ATCA_NO_DEVICES:
        return PSA_ERROR_COMMUNICATION_FAILURE;
    case ATCA_UNIMPLEMENTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case ATCA_ALLOC_FAILURE:
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    case ATCA_CONFIG_ZONE_LOCKED:
    case ATCA_DATA_ZONE_LOCKED:
    case ATCA_NOT_LOCKED:
    case ATCA_WAKE_FAILED:
    case ATCA_STATUS_UNKNOWN:
    case ATCA_STATUS_ECC:
    case ATCA_STATUS_SELFTEST_ERROR:
    case ATCA_CHECKMAC_VERIFY_FAILED:
    case ATCA_PARSE_ERROR:
    case ATCA_FUNC_FAIL:
    case ATCA_GEN_FAIL:
    case ATCA_EXECUTION_ERROR:
    case ATCA_HEALTH_TEST_ERROR:
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

/* Lazy init the hardware. Might want to consider adding a "probe" or "init"
 * function to PSA Crypto to init drivers */
static int atecc608a_init(void)
{
    if (!inited)
    {
        ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
        inited = 1;
    }

    return 0;
}

static int atecc608a_deinit()
{
    if (inited)
    {
        ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
        inited = 0;
    }

    return 0;
}

psa_status_t atecc608a_asymmetric_sign(psa_key_slot_number_t key_slot,
                                       psa_algorithm_t alg,
                                       const uint8_t *p_hash,
                                       size_t hash_length,
                                       uint8_t *p_signature,
                                       size_t signature_size,
                                       size_t *p_signature_length)
{
    ATCA_STATUS ret = ATCA_SUCCESS;
    uint16_t key_id = key_slot;

    /* We can only do ECDSA on SHA-256 */
    /* PSA_ALG_ECDSA(PSA_ALG_SHA_256) */
    if(!PSA_ALG_IS_ECDSA(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_length != 32)
    {
        /* The driver only supports signing things of length 32. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!PSA_ALG_IS_RANDOMIZED_ECDSA(alg))
    {
        /* The hardware only supports randomized ECDSA */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* XXX how to check the curve? */
    //PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1);
    //PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256K1);

    atecc608a_init();

    /* Signature will be returned here. Format is R and S integers in
     * big-endian format. 64 bytes for P256 curve. */
    ret = atcab_sign(key_id, p_hash, p_signature);
    if (ret != ATCA_SUCCESS)
    {
        return atecc608a_to_psa_error(ret);
    }

    *p_signature_length = 32;
    atecc608a_deinit();

    return atecc608a_to_psa_error(ret);
}

psa_status_t atecc608a_asymmetric_verify(psa_key_slot_number_t key_slot,
                                         psa_algorithm_t alg,
                                         const uint8_t *p_hash,
                                         size_t hash_length,
                                         const uint8_t *p_signature,
                                         size_t signature_length);

static psa_drv_se_asymmetric_t atecc608a_asymmetric =
{
    .p_sign = 0,
    .p_verify = 0,
    .p_encrypt = 0,
    .p_decrypt = 0,
};

// psa_drv_se_key_management_t *p_key_management;
// psa_drv_se_mac_t *p_mac;
// psa_drv_se_cipher_t *p_cipher;
// psa_drv_se_asymmetric_t *p_asym;
// psa_drv_se_aead_t *p_aead;
// psa_drv_se_key_derivation_t *p_derive;

static psa_drv_se_info_t atecc608a_drv_info = {
    .lifetime = PSA_ATECC608A_LIFETIME,
    //psa_drv_se_key_management_t *p_key_management;
    //psa_drv_se_mac_t *p_mac;
    //psa_drv_se_cipher_t *p_cipher;
    .p_asym = &atecc608a_asymmetric,
    //psa_drv_se_aead_t *p_aead;
    //psa_drv_se_key_derivation_t *p_derive;
    .slot_min = 10,
    .slot_max = 12,
};

int main(void)
{
    enum {
        key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1),
        keypair_type = PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1),
        key_bits = 256,
        hash_alg = PSA_ALG_SHA_256,
        alg = PSA_ALG_ECDSA(hash_alg),
        sig_size = PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg),
        pubkey_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits),
        hash_size = PSA_HASH_SIZE(hash_alg),
    };
    psa_status_t status;
    psa_key_handle_t sign_handle;
    psa_key_handle_t verify_handle;
    uint8_t signature[sig_size];
    size_t signature_length = 0;
    const uint8_t hash[hash_size] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    static uint8_t pubkey[pubkey_size];
    size_t pubkey_len = 0;
    psa_key_slot_number_t atecc608a_key_slot = 10;

    printf("**********************************************\n");
    read_serial_number();

    printf("**********************************************\n");
    hash_sha256(hash_input1, sizeof(hash_input1) - 1,
                sha256_expected_hash1, sizeof(sha256_expected_hash1));

    printf("**********************************************\n");
    hash_sha256(hash_input2, sizeof(hash_input2) - 1,
                sha256_expected_hash2, sizeof(sha256_expected_hash2));

    /* XXX Call this before or after registering SE? */
    status = psa_crypto_init();
    ASSERT_STATUS(status, PSA_SUCCESS);

    /* Register SE */
    status = psa_register_secure_element(atecc608a_drv_info);
    ASSERT_STATUS(status, PSA_SUCCESS);

    /* TODO Register some pre-provisioned SE slots */
    //status = psa_register_se_slot(
    //    psa_key_id_t id,
    //    psa_key_slot_number_t slot,
    //    psa_key_lifetime_t lifetime,
    //    psa_key_type_t key_type,
    //    size_t size,
    //    uint8_t occupied,
    //    int32_t owner);

    /* TODO Program the device with some configuration in order to enable it to
     * sign something? Suggest to copy Azim's for testing configuration, if
     * needed. Read entire datasheet to find out (cover to cover). */

    /* TODO Make a signature */
    /* Come up with a test vector. Signature is randomized, so we need to
     * verify with software. */
#if USE_SE
    status = atecc608a_asymmetric_sign(
        atecc608a_key_slot, alg, &hash, sizeof(hash),
        signature, sizeof(signature), &signature_length);
    ASSERT_STATUS(status, PSA_SUCCESS);
#else
    /*
     * Generate a volatile keypair in a volatile key slot.
     */
    {

    status = psa_allocate_key(&sign_handle);
    ASSERT_STATUS(status, PSA_SUCCESS);

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_SIGN, alg);
    status = psa_set_key_policy(sign_handle, &policy);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_generate_key(sign_handle, keypair_type, key_bits, NULL, 0);
    ASSERT_STATUS(status, PSA_SUCCESS);

    /* Sign a hash. */
    status = psa_asymmetric_sign(
        sign_handle, alg, hash, sizeof(hash),
        signature, sizeof(signature), &signature_length);
    ASSERT_STATUS(status, PSA_SUCCESS);

    printf("derp\n");
    status = psa_export_public_key(
        sign_handle, pubkey, sizeof(pubkey), &pubkey_len);
    ASSERT_STATUS(status, PSA_SUCCESS);
    printf("pubkey_len: %lu\n", pubkey_len);
    printf("pubkey:\n");
    hexdump(pubkey, pubkey_len);

    printf("signature_len: %lu\n", signature_length);
    printf("signature:\n");
    hexdump(signature, signature_length);
    }
#endif

    /*
     * Import the secure element's public key into a volatile key slot.
     */
    status = psa_allocate_key(&verify_handle);
    ASSERT_STATUS(status, PSA_SUCCESS);

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, alg);
    status = psa_set_key_policy(verify_handle, &policy);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_import_key(verify_handle, key_type, pubkey, pubkey_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    /* Verify that the signature produced by the secure element is valid. */
    status = psa_asymmetric_verify(verify_handle, alg, hash, sizeof(hash),
                                   signature, signature_length);
    ASSERT_STATUS(status, PSA_SUCCESS);

    return 0;
}
#else
int main(void)
{
    printf("Not all of the required options are defined:\n"
           "  - ATCA_HAL_I2C\n");
    return 0;
}
#endif
