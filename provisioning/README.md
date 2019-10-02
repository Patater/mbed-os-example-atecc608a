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