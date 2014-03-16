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

            NSString kSecAttrKeyType;
            NSString kSecAttrKeySizeInBits;
            NSString kSecAttrKeyTypeRSA;

            IntPtr handle = Dlfcn.dlopen(Constants.SecurityLibrary, 0);
            Assumes.False(handle == IntPtr.Zero);

            try
            {
                kSecAttrKeyType = Dlfcn.GetStringConstant(handle, "kSecAttrKeyType");
                kSecAttrKeySizeInBits = Dlfcn.GetStringConstant(handle, "kSecAttrKeySizeInBits");
                kSecAttrKeyTypeRSA = Dlfcn.GetStringConstant(handle, "kSecAttrKeyTypeRSA");
            }
            finally
            {
                Dlfcn.dlclose(handle);
            }

            NSObject[] keys = new NSObject[] 
            { 
                kSecAttrKeyType, 
                kSecAttrKeySizeInBits 
            };
            NSObject[] values = new NSObject[] 
            { 
                kSecAttrKeyTypeRSA, 
                new NSNumber(keySize) 
            };

            SecKey publicKey;
            SecKey privateKey;

            NSDictionary parameters = NSDictionary.FromObjectsAndKeys(values, keys);

            SecStatusCode code = SecKey.GenerateKeyPair(parameters, out publicKey, out privateKey);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);

            return new RsaCryptographicKey(publicKey, privateKey, this.algorithm);
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

            return new RsaCryptographicKey(publicKey, privateKey, this.algorithm);
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

            return new RsaCryptographicKey(publicKey, this.algorithm);
        }
    }
}
