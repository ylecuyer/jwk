# DER Encoded ASN.1

* Everything is Big Endian.
* Every encoded item is prefixed by a tag that specifies its nature followed by its length and data.
* If lengths are < 128 they are just added to the stream as a single byte. Lengths > 127 are prefixed by (0x80 | bytelength of length).
* If Tags have 0x80 bit set, they're "custom". If 0xA0, they're custom, but structured like a SEQUENCE.

### Notable tags:

* **0x30** SEQUENCE (array of non-uniform objects)
* **0x02** INTEGER
* **0x03** BIT STRING (for some reason prefixed by 00)
* **0x04** OCTET STRING (similar to BIT STRING but not prefixed by 00)
* **0x05** NULL
* **0x06** OBJECT IDENTIFIER

## Generic Public Key format:

    SEQUENCE
      SEQUENCE
        OBJECT IDENTIFIER
        NULL
      BIT STRING
        (Key Type dependent)

## RSA Public Key format:

Can be found in the wild, but it is usually embedded in the Generic Public Key format.

    SEQUENCE
      INTEGER n
      INTEGER e

## RSA Private Key format:

    SEQUENCE (0x30)
      INTEGER 0
      INTEGER n
      INTEGER e
      INTEGER d
      INTEGER p
      INTEGER q
      INTEGER dp
      INTEGER dq
      INTEGER qi

## EC Private Key format:

    SEQUENCE
      INTEGER 1
      OCTET STRING d
      (custom structure, 0xA0)
        OBJECT IDENTIFIER
      (custom structure, 0xA1)
        BIT STRING (0x04 followed by x and y)

## Common Object IDs

RSA: 1.2.840.113549.1.1.1
EC P-256: 1.2.840.10045.3.1.7
EC P-384: 1.3.132.0.34
EC P-521: 1.3.132.0.35
