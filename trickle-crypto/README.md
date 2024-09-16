# Trickle Crypto

## Noise Protocol
Custom implimentation of the [Noise](https://noiseprotocol.org/) protocol framework rev. #34.
Notes:
- Lacks ability to use more then one preshared key (ie. psk not psk0).
Features:
- Optionally includes Kyber-512/1024 for quantum resistant hybrid forward secrecy (behind feature "hfs").
- AESGCM 256-bit cipher
- ChaCha20Poly1305 cipher
- SHA256 hash
- SHA512 hash
- SHA3-256 hash
- BLAKE2s hash
- BLAKE2d hash
- BLAKE3 hash
