# Mbed Crypto provisioning example application

Let's say the secure element manufacturer shipped you a secure element with a
device private key already inside. This type of "pre-provisioned" secure
element is what you'll use as a part during the device assembly process. You've
taken this secure element, paired it with a nice Cortex-M microcontroller on a
board to make a device. Now, you'd like to be able to use this key from Mbed
Crypto. How does Mbed Crypto know the key exists? We can tell Mbed Crypto by
running a provisionining application, which is typically separate from the
primary application and may be run as a final device assembly step.


### Adding pre-provisioned keys

Mbed Crypto provides a way to register pre-existing secure element keys:
`mbedtls_psa_register_se_key()`. This function adds the necessary metadata to
persistent storage so that the secure element keys can be used by an
application key ID.

Provide which physical secure element slot the key is in with
`psa_set_key_slot_number()`. This function operates on a key attributes
structure. Complete the filling in of all necessary attributes and then call
`mbedtls_psa_register_se_key()` to notify Mbed Crypto that the key exists,
where the key exists, what format the key is, what the key can be used for, and
so forth.


### This example requires a certificate authority

For the sake of this example, we'll assume you have three certificate
authorities (CAs): a Root CA, a Server Sub-CA, and a Device Sub-CA. We'll
assume you want to use openssl to run this test CA. We assume the following
file names for the relevant files that comprise your CA, and that the file
contents are PEM encoded.

*Root CA*
The Root CA is used to create subordinate CAs. Its certificate is used by both
servers and devices in a certificate chain.
- Private key in `RootCA.key`
- Root certificate in `RootCA.crt`

*Server Sub-CA*
The Server Sub-CA is used to sign a server's CSR to produce a server
certificate.
- Private key in ServerSub.key
- Server Sub-CA certificate in ServerSub.crt

*Device Sub-CA*
- Private key in DeviceSub.key
- Device Sub-CA certificate in DeviceSub.crt

We also assume the presence of the following certificate chains:

*Server certificate chain*
- The Root CA certificate followed by the Server Sub-CA certificate in
  ServerChain.pem
- The server certificate chain is used by devices to authenticate servers they
  connect to.

*Device certificate chain*
- The Root CA certificate followed by the Device Sub-CA certificate in
  DeviceChain.pem
- The device certificate chain is used by servers to authenticate devices,
  enabling mutually authenticated TLS connections.


### Using device-generated CSRs

This example generates certificate signing requests (CSRs) which can be used
for TLS client authentication. The CSR is printed over the serial port, for
use with your certificate authority (CA).

The Device Sub-CA will consume the device-generated certificate signing request
and produce a certificate for the device which you can use in the TLS with
client authentication example also included in this repository (in the
`mutual-tls` folder).

1. Run the provisioning example
1. Create a new file on your host machine to hold the CSR from the device,
   called `Device.csr`.
1. Copy paste the device-generate CSR text from your devices console output
   into this file.
1. Run the following openssl command to make your CA generate a certificate
    ```
    openssl x509 -req -sha256 -CA DeviceSub.crt -CAkey DeviceSub.key \
    -in Device.csr -out Device.crt \
    -set_serial 0xbeef07d131eee6dcdcba0db720b33ecc -days 730 -extensions v3
    ```
1. View your generated certificate with this openssl command:
    ```
    openssl x509 -in Device.crt -text | less
    ```
1. Verify your generated certificate with this openssl command:
    ```
    openssl verify -CAfile DeviceChain.pem Device.crt
    ```
1. Copy the `Device.crt` file to the `mutual-tls` example folder for use with
   making a mutually-authenticated TLS connection, and follow the directions in
   that example's README.
