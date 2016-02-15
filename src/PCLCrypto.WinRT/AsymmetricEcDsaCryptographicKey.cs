// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using static PInvoke.NCrypt;

    /// <summary>
    /// A cryptographic key for ECDSA operations.
    /// </summary>
    internal class AsymmetricEcDsaCryptographicKey : NCryptAsymmetricKeyBase
    {
        internal AsymmetricEcDsaCryptographicKey(NCryptAsymmetricKeyProviderBase provider, SafeKeyHandle key, bool isPublicOnly)
            : base(provider, key, isPublicOnly)
        {
        }
    }
}
