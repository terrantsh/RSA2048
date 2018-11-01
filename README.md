# RSA2048

### Public key encryption, private key decryption;Private key encryption, public key decryption.

Implement RSA algorithm based on C language, support public key encrypted, decrypted, private key encrypted, decrypted.

### among them:

  Function RSA2048 is used to encrypt and decrypt.

  此工程实现了RSA2048利用已有公钥私钥进行加密解密，需要注意的一点是，在实现过程中，私钥加密公钥解密过程中，随机位的填充是以0x00座位标志位的，所以需要加密的数据在0x00之后的部分可能不会被解密。
