// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Formatters;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// An RSA asymmetric cryptographic key backed by the Win32 crypto library.
    /// </summary>
    internal class AsymmetricRsaCryptographicKey : NCryptAsymmetricKeyBase, ICryptographicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricRsaCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The BCrypt cryptographic key handle.</param>
        /// <param name="algorithm">The asymmetric algorithm used by this instance.</param>
        internal AsymmetricRsaCryptographicKey(AsymmetricKeyRsaAlgorithmProvider provider, SafeKeyHandle key, bool isPublicOnly)
            : base(provider, key, isPublicOnly)
        {
        }
    }
}
