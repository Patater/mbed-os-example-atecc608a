# Provisioning Mbed Crypto example application

Let's say the secure element factory gave you a secure element with a device
private key already inside. You've taken this secure element, paired it with a
nice Cortex-M microcontroller on a board to make a device. Now, you'd like to
be able to use this key from Mbed Crypto. How does Mbed Crypto know the key
exists?

### Adding pre-provisioned keys

Mbed Crypto provides a way to register pre-existing secure element keys:
`mbedtls_psa_register_se_key()`. This function adds the necessary metadata to
persistent storage so that the secure element keys can be used by an
application key ID.

Provide which physical secure element slot is the key in with
`psa_set_key_slot_number()`. This function operates on a key attributes
structure. Complete the filling in of all necessary attributes and then call
`mbedtls_psa_register_se_key()` to notify Mbed Crypto that the key exists,
where the key exists, what format the key is, what the key can be used for, and
so forth.

### Using device-generated CSRs

This example generates certificate signing requests (CSRs) which can be used
for TLS client authentication. The CSR is printed over the serial port, for
use with your certificate authority (CA).

For this example, we'll assume you have three CAs. A Root CA, a Server Sub-CA,
and a Device Sub-CA. The Device Sub-CA is what will consume the
device-generated certificate signing request, and produce a certificate for the
device which you can use in the TLS with client authentication example also
included in this repository.

1. Run the provisioning example
1. Create a new file on your host machine to hold the CSR from the device,
called `Device.csr`.
1. Copy paste the device-generate CSR text into this file.
1. Run the following openssl command to make your CA generate a certificate
   (XXX maybe we should share the commands to set up the CAs, or include all
   the keys for the test CA in this repo):
    ```
    openssl x509 -req -sha256 -CA DeviceSub.crt -CAkey DeviceSub.key \
    -in Device.csr -out Device.crt \
    -set_serial 0xbeef07d131eee6dcdcba0db720b33ecc -days 730 -extensions v3
    ```
1. View your generated certificate with this openssl command:
    ```
    openssl x509 -in Device.crt -text | less
    ```
