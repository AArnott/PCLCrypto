//-----------------------------------------------------------------------
// <copyright file="CryptographicKey.cs" company="Andrew Arnott">
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

    /// <summary>
    /// The .NET Framework implementation of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal class CryptographicKey : ICryptographicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey"/> class.
        /// </summary>
        internal CryptographicKey()
        {
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotImplementedException();
        }
    }
}
