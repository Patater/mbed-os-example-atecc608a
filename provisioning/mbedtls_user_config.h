/*
 *  Copyright (C) 2006-2019, Arm Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

/* Enable PSA APIs, which this example depends on. */
#if !defined(MBEDTLS_PSA_CRYPTO_C)
#   define MBEDTLS_PSA_CRYPTO_C
#endif

/* Enable PSA use of secure elements. */
#if !defined(MBEDTLS_PSA_CRYPTO_SE_C)
#    define MBEDTLS_PSA_CRYPTO_SE_C
#endif

/* Make Mbed TLS use PSA. */
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#    define MBEDTLS_USE_PSA_CRYPTO
#endif

/* Enable features needed to generate a CSR */
//#define MBEDTLS_CTR_DRBG_C
//#define MBEDTLS_ENTROPY_C
#define MBEDTLS_PEM_WRITE_C
//#define MBEDTLS_PK_PARSE_C
//#define MBEDTLS_SHA256_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CSR_WRITE_C
