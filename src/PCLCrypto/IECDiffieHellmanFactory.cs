// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// A factory for instances of <see cref="IECDiffieHellman"/>.
    /// </summary>
    public interface IECDiffieHellmanFactory
    {
        /// <summary>
        /// Creates an instance of an <see cref="IECDiffieHellman"/>
        /// with a new key.
        /// </summary>
        /// <returns>An instance of <see cref="IECDiffieHellman"/>.</returns>
        IECDiffieHellman Create();
    }
}
