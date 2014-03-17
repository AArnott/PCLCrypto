//-----------------------------------------------------------------------
// <copyright file="RsaAsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using MonoTouch;
    using MonoTouch.Foundation;
    using MonoTouch.ObjCRuntime;
    using MonoTouch.Security;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of RSA.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            string keyIdentifier = Guid.NewGuid().ToString();
            string publicKeyIdentifier = RsaCryptographicKey.GetPublicKeyIdentifierWithTag(keyIdentifier);
            string privateKeyIdentifier = RsaCryptographicKey.GetPrivateKeyIdentifierWithTag(keyIdentifier);

            // Configure parameters for the joint keypair.
            var keyPairAttr = new NSMutableDictionary();
            keyPairAttr[KSec.AttrKeyType] = KSec.AttrKeyTypeRSA;
            keyPairAttr[KSec.AttrKeySizeInBits] = NSNumber.FromInt32(keySize);

            // Configure parameters for the private key
            var privateKeyAttr = new NSMutableDictionary();
            privateKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            privateKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(privateKeyIdentifier, NSStringEncoding.UTF8);

            // Configure parameters for the public key
            var publicKeyAttr = new NSMutableDictionary();
            publicKeyAttr[KSec.AttrIsPermanent] = NSNumber.FromBoolean(true);
            publicKeyAttr[KSec.AttrApplicationTag] = NSData.FromString(publicKeyIdentifier, NSStringEncoding.UTF8);

            // Parent the individual key parameters to the keypair one.
            keyPairAttr[KSec.PublicKeyAttrs] = publicKeyAttr;
            keyPairAttr[KSec.PrivateKeyAttrs] = privateKeyAttr;

            // Generate the RSA key.
            SecKey publicKey, privateKey;
            SecStatusCode code = SecKey.GenerateKeyPair(keyPairAttr, out publicKey, out privateKey);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);

            return new RsaCryptographicKey(publicKey, privateKey, keyIdentifier, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            SecKey privateKey, publicKey;
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    throw new NotImplementedException();
                default:
                    throw new NotSupportedException();
            }

            return new RsaCryptographicKey(publicKey, privateKey, null, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            SecKey publicKey;
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                    throw new NotImplementedException();
                default:
                    throw new NotSupportedException();
            }

            return new RsaCryptographicKey(publicKey, null, this.algorithm);
        }
    }
}
