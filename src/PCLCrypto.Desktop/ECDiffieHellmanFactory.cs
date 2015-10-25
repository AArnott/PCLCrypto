// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The desktop and other .NET platforms implementation of <see cref="IECDiffieHellmanFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanFactory : IECDiffieHellmanFactory
    {
        /// <inheritdoc />
        public IECDiffieHellman Create()
        {
            return new ECDiffieHellman(Platform.ECDiffieHellman.Create());
        }
    }
}
