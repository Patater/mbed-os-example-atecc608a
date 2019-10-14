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
#include "TCPSocket.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"
#include "psa/lifecycle.h"
#include "atecc608a_se.h"

/* The application-specific key ID for the device private key. */
#define EXAMPLE_DEVICE_KEY_ID 3

#define TEST_MACHINE_IP "10.2.202.186"

/* Chain of trusted CAs in PEM format */
static const unsigned char tls_pem_ca[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
    "rqXRfboQnoZsG4q5WTP468SQvvG5\n"
    "-----END CERTIFICATE-----\n";

/* Client certificate for TLS client authentication in PEM format */
static const unsigned char tls_client_crt[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBaTCCAQ4CEQC+7wfRMe7m3Ny6Dbcgsz7MMAoGCCqGSM49BAMCMC4xEjAQBgNV\n"
    "BAMMCURldmljZVN1YjELMAkGA1UEBhMCVUsxCzAJBgNVBAsMAkNBMB4XDTE5MTAx\n"
    "MTE2NDk1NloXDTIxMTAxMDE2NDk1NlowQjEPMA0GA1UEAwwGRGV2aWNlMREwDwYD\n"
    "VQQKDAhNYmVkIFRMUzEPMA0GA1UECwwGY2xpZW50MQswCQYDVQQGEwJVSzBZMBMG\n"
    "ByqGSM49AgEGCCqGSM49AwEHA0IABITdntuC6BsjdYwYam/u5qI3V8PyspDCZ5v2\n"
    "3eI/gcVLAYBzha/75JMcsdsLwMOq89Lo56Ae1k6qAZOhwO4g34wwCgYIKoZIzj0E\n"
    "AwIDSQAwRgIhAMLb7nQ377J5P3ox5DuNJNib3F9mrbTPTVjaxSK54/XtAiEA4FWX\n"
    "rcwFgYBGlR3n+gpOmlIRWwMhKUjKJH77eW6CMiM=\n"
    "-----END CERTIFICATE-----\n";

/* Server to connect to */
static const char *server = "os.mbed.com";

/* Mbed TLS contexts */
mbedtls_platform_context platform_ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;
mbedtls_ssl_context ssl;
mbedtls_ssl_config ssl_conf;

int my_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret;

    ret = socket->send(buf, len);
    if (ret == NSAPI_ERROR_WOULD_BLOCK) {
        ret = MBEDTLS_ERR_SSL_WANT_WRITE;
    } else if (ret < 0) {
        printf("socket.send() returned %d\n", ret);
    }

    return ret;
}

int my_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret;

    ret = socket->recv(buf, len);
    if (ret == NSAPI_ERROR_WOULD_BLOCK) {
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    } else if (ret < 0) {
        printf("socket.recv() returned %d\n", ret);
    }

    return ret;
}

int init(void)
{
    int ret;

    ret = mbedtls_platform_setup(&platform_ctx);
    if (ret != 0) {
        printf("Platform initialization failed with error %d\r\n", ret);
        return MBEDTLS_EXIT_FAILURE;
    }

    /* TODO How can Mbed TLS use PSA's entropy? It shouldn't need to if it can
     * use psa_get_random(). */
    mbedtls_entropy_init(&entropy);
    if (ret != 0) {
        printf("failed with error %d\r\n", ret);
        return MBEDTLS_EXIT_FAILURE;
    }

    /* TODO How can Mbed TLS use PSA's DRBG? Make Mbed TLS call
     * psa_get_random() */
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);

    static const char *personalization = "Mbed OS Example ATECC608A";

    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy,
        reinterpret_cast<const unsigned char*>(personalization),
        sizeof(personalization));
    if (ret != 0) {
        printf("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_x509_crt_parse(&cacert, tls_pem_ca, sizeof(tls_pem_ca));
    if (ret != 0) {
        printf("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("mbedtls_ssl_config_defaults() returned -0x%04X\n",
                       -ret);
        return ret;
    }

    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    ret = mbedtls_ssl_setup(&ssl, &ssl_conf);
    if (ret != 0) {
        printf("mbedtls_ssl_setup() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, server);
    if (ret != 0) {
        printf("mbedtls_ssl_set_hostname() returned -0x%04X\n", -ret);
        return ret;
    }

    return 0;
}

int main(void)
{
    psa_status_t status;
    nsapi_size_or_error_t ret;

    if (init() != 0)
    {
        return -1;
    }

    printf("Connecting to TLS server...\n");

    printf("\tInitializing PSA Crypto... ");
    fflush(stdout);
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("failed with status=%ld\n", status);
        return status;
    }
    printf("done.\n");

    printf("\tGetting network... ");
    fflush(stdout);
    NetworkInterface *net = NetworkInterface::get_default_instance();
    if (net == NULL) {
        printf("ERROR: No network interface found!\n");
        return -1;
    }
    ret = net->connect();
    if (ret != 0) {
        printf("failed with ret=%d\n", ret);
        return ret;
    }
    printf("done\n");

    TCPSocket *socket = new TCPSocket();

    mbedtls_ssl_set_bio(&ssl, static_cast<void *>(socket),
                        my_ssl_send, my_ssl_recv, NULL);

    //socket->set_blocking(false);
    printf("\tOpening socket... ");
    fflush(stdout);
    ret = socket->open(net);
    if (ret != 0) {
        printf("failed with ret=%d\n", ret);
        return ret;
    }
    printf("done\n");

    printf("\tConnecting... ");
    fflush(stdout);
    ret = socket->connect(server, 443);
    if (ret != 0) {
        printf("failed with ret=%d\n", ret);
        return ret;
    }
    printf("done\n");

    /* Start the TLS handshake */
    printf("\tHanshaking with TLS...");
    fflush(stdout);
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret != 0 &&
             (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        printf("failed with -ret=-0x%04X\n", -ret);
        return ret;
    }
    printf("done\n");

    /* Fill the request buffer */
    printf("\tMaking HTTPS request...");
    fflush(stdout);
    static const char *path = "/media/uploads/mbed_official/hello.txt";
    static char gp_buf[512];
    ret = snprintf(gp_buf, sizeof(gp_buf),
                   "GET %s HTTP/1.1\nHost: %s\n\n", path,
                   server);
    size_t req_len = static_cast<size_t>(ret);
    if (ret < 0 || req_len >= sizeof(gp_buf)) {
        printf("Failed to compose HTTP request using snprintf: %d\n",
                       ret);
        return ret;
    }

    /* Send the HTTP request to the server over TLS */
    size_t req_offset = 0;
    do {
        ret = mbedtls_ssl_write(&ssl,
                reinterpret_cast<const unsigned char *>(gp_buf + req_offset),
                req_len - req_offset);
        if (ret > 0)
            req_offset += static_cast<size_t>(ret);
    } while (req_offset < req_len &&
             (ret > 0 ||
              ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
              ret == MBEDTLS_ERR_SSL_WANT_READ));
    if (ret < 0) {
        printf("failed with -ret=-0x%04X\n", -ret);
        return ret;
    }
    printf("done\n");

    /* Print information about the TLS connection */
    ret = mbedtls_x509_crt_info(gp_buf, sizeof(gp_buf),
                                "\r  ", mbedtls_ssl_get_peer_cert(&ssl));
    if (ret < 0) {
        printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
        return ret;
    }
    printf("Server certificate:\n%s\n", gp_buf);

    /* Ensure certificate verification was successful */
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        ret = mbedtls_x509_crt_verify_info(gp_buf, sizeof(gp_buf),
                                           "\r  ! ", flags);
        if (ret < 0) {
            printf("mbedtls_x509_crt_verify_info() returned "
                           "-0x%04X\n", -ret);
            return ret;
        } else {
            printf("Certificate verification failed (flags %lu):"
                           "\n%s\n", flags, gp_buf);
            return -1;
        }
    } else {
        printf("Certificate verification passed\n");
    }

    printf("Established TLS connection to %s\n", server);

    /* Read response from the server */
    size_t resp_offset = 0;
    bool resp_200 = false;
    bool resp_hello = false;
    do {
        ret = mbedtls_ssl_read(&ssl,
                    reinterpret_cast<unsigned char *>(gp_buf + resp_offset),
                    sizeof(gp_buf) - resp_offset - 1);
        if (ret > 0) {
            resp_offset += static_cast<size_t>(ret);
        }

        /* Ensure that the response string is null-terminated */
        gp_buf[resp_offset] = '\0';

        /* Check  if we received expected string */
        resp_200 = resp_200 || strstr(gp_buf, "200 OK") != NULL;
        resp_hello = resp_hello || strstr(gp_buf, "Hello world!") != NULL;
    } while((!resp_200 || !resp_hello) &&
            (ret > 0 ||
            ret == MBEDTLS_ERR_SSL_WANT_READ || MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        printf("mbedtls_ssl_read() returned -0x%04X\n", -ret);
        return ret;
    }

    /* Display response information */
    printf("HTTP: Received %u chars from server\n", resp_offset);
    printf("HTTP: Received '%s' status ... %s\n",
           "200 OK", resp_200 ? "OK" : "FAIL");
    printf("HTTP: Received message:\n%s\n", gp_buf);

    /* TODO Tell Mbed TLS to use the device key as the TLS client key. */

    printf("Success\n");
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
