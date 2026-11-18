"""Thin, well-commented wrappers around the `cryptography` library.

Nothing in this package implements a cryptographic primitive by hand.
Every algorithm (scrypt, AES-GCM, RSA-OAEP, Ed25519) comes from the
`cryptography` library; this package only chooses parameters and glues
the pieces together so the rest of the app reads clearly.

Modules:
    encoding   - base64 helpers and canonical JSON for signing
    passwords  - salted password hashing (server side)
    keys       - key pairs and password-protected private-key storage (client side)
    messages   - the end-to-end message format: encrypt + sign, verify + decrypt
"""
