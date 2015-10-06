//-----------------------------------------------------------------------
// <copyright file="IECDiffieHellmanFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
