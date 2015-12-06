// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Offers functionality similar to CryptographicEngine in WinRT.
    /// </summary>
    public interface ICryptographicEngine
    {
        /// <summary>
        /// Encrypts data by using a symmetric or asymmetric algorithm.
        /// </summary>
        /// <param name="key">
        /// Cryptographic key to use for encryption. This can be an asymmetric or a symmetric
        /// key. For more information, see AsymmetricKeyAlgorithmProvider and SymmetricKeyAlgorithmProvider.
        /// </param>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="iv">
        /// Buffer that contains the initialization vector. This can be null for a symmetric
        /// algorithm and should always be null for an asymmetric algorithm. If an initialization
        /// vector (IV) was used to encrypt the data, you must use the same IV to decrypt
        /// the data. You can use the GenerateRandom method to create an IV that contains
        /// random data. Other IVs, such as nonce-generated vectors, require custom implementation.
        /// For more information, see Symmetric Key Encryption.Cipher block chaining
        /// (CBC) block cipher mode algorithms require an initialization vector. For
        /// more information, see Remarks.
        /// </param>
        /// <returns>Encrypted data.</returns>
        byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv = null);

        /// <summary>
        /// Creates a cryptographic transform for use in a CryptoStream
        /// that encrypts data.
        /// </summary>
        /// <param name="key">The encryption key to use.</param>
        /// <param name="iv">The initialization vector, if applicable and nonzero.</param>
        /// <returns>The transform.</returns>
        ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv = null);

        /// <summary>
        /// Decrypts content that was previously encrypted by using a symmetric or asymmetric
        /// algorithm.
        /// </summary>
        /// <param name="key">
        /// Cryptographic key to use for decryption. This can be an asymmetric or a symmetric
        /// key. For more information, see AsymmetricKeyAlgorithmProvider and SymmetricKeyAlgorithmProvider.
        /// </param>
        /// <param name="data">
        /// Buffer that contains the encrypted data.
        /// </param>
        /// <param name="iv">
        /// Buffer that contains the initialization vector. If an initialization vector
        /// (IV) was used to encrypt the data, you must use the same IV to decrypt the
        /// data. For more information, see Encrypt.
        /// </param>
        /// <returns>Decrypted data.</returns>
        byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv = null);

        /// <summary>
        /// Creates a cryptographic transform for use in a CryptoStream
        /// that decrypts data.
        /// </summary>
        /// <param name="key">The decryption key to use.</param>
        /// <param name="iv">The initialization vector, if applicable and nonzero.</param>
        /// <returns>The transform.</returns>
        ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv = null);

        /// <summary>
        /// Signs digital content.
        /// </summary>
        /// <param name="key">Key used for signing.</param>
        /// <param name="data">Data to be signed.</param>
        /// <returns>The signature.</returns>
        byte[] Sign(ICryptographicKey key, byte[] data);

        /// <summary>
        /// Signs the hashed input data using the specified key.
        /// </summary>
        /// <param name="key">The key to use to sign the hash.</param>
        /// <param name="data">
        /// The input data to sign. The data is a hashed value which can be obtained
        /// through incremental hash.
        /// </param>
        /// <returns>The signature.</returns>
        byte[] SignHashedData(ICryptographicKey key, byte[] data);

        /// <summary>
        /// Verifies a message signature.
        /// </summary>
        /// <param name="key">
        /// Key used for verification. This must be the same key previously used to sign
        /// the message.
        /// </param>
        /// <param name="data">Message to be verified.</param>
        /// <param name="signature">Signature previously computed over the message to be verified.</param>
        /// <returns>true if the message is verified.</returns>
        bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature);

        /// <summary>
        /// Verifies the signature of the specified input data against a known signature.
        /// </summary>
        /// <param name="key">
        /// The key to use to retrieve the signature from the input data.
        /// </param>
        /// <param name="data">The data to be verified. The data is a hashed value of raw data.</param>
        /// <param name="signature">The known signature to use to verify the signature of the input data.</param>
        /// <returns>True if the signature is verified; otherwise false.</returns>
        bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature);

        /// <summary>
        /// Derives a key from another key by using a key derivation function.
        /// </summary>
        /// <param name="key">The symmetric or secret key used for derivation.</param>
        /// <param name="parameters">Derivation parameters. The parameters vary depending on the type of KDF algorithm
        /// used.</param>
        /// <param name="desiredKeySize">Requested size, in bytes, of the derived key.</param>
        /// <returns>
        /// Buffer that contains the derived key.
        /// </returns>
        byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize);
    }
}
