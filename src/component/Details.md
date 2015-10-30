
PCLCrypto is an [open source library][1] that provides portable class library 
authors with cryptographic APIs that invoke platform-specific crypto 
automatically.

## Features

 * Cryptographically strong random number generator 
 * Symmetric and asymmetric encryption and signatures 
 * Key derivation 
 * Native crypto performance for each platform. This provides a 2-100X perf 
   improvement for RSA on Android and iOS. 
 * Support for multiple key formats (PKCS#1, PKCS#8, CAPI) on all platforms. 

This library does not implement crypto. It merely provides PCL-compatible APIs 
to invoke crypto, and at runtime the crypto offered by the platform is invoked. 
So you should be able to trust the crypto available through this library almost 
as much as you can trust the crypto in the operating system you're already 
running on.

The API is designed to be similar to that found on WinRT or the .NET Framework. 
However some code changes may be required if migrating to this library from 
platform-specific crypto.

## Documentation

Online documentation is available on our [project wiki site][2].

## Usage

There are many ways to make use of cryptography, but here are some quick 
examples. 

### Encryption

An example of encryption of text using the RSA public key algorithm that uses 
PKCS1 to pad the plaintext.

    using PCLCrypto;
    using static PCLCrypto.WinRTCrypto;
    ...
    
    var asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
    var key = asym.CreateKeyPair(512);
    
    var plain = Encoding.UTF8.GetBytes("PLAIN_TEXT_STRING");
    var encrypted = CryptographicEngine.Encrypt(key, plain);
    var encryptedString = Convert.ToBase64String(encrypted);

### Decryption

An example of decryption of data using the RSA public key algorithm that uses 
PKCS1 to pad the plaintext.

    using PCLCrypto;
    using static PCLCrypto.WinRTCrypto;
    ...
    
    var asym = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1);
    var key = asym.CreateKeyPair(512);
    
    var encrypted = Convert.FromBase64String("ENCRYPTED_STRING");
    var decrypted = CryptographicEngine.Decrypt(key, encrypted);
    var decryptedString = Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);

### Hashing

An example of hashing using the Secure Hash Algorithm 1 algorithm.

    using PCLCrypto;
    using static PCLCrypto.WinRTCrypto;
    ...
    
    var hash = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
    
    var plain = Encoding.UTF8.GetBytes("PLAIN_TEXT_STRING");
    var hashed = hash.HashData(plain);
    var hashedString = Convert.ToBase64String(hashed);

 [1]: http://github.com/aarnott/pclcrypto
 [2]: https://github.com/aarnott/pclcrypto/wiki
