//-----------------------------------------------------------------------
// <copyright file="ECDiffieHellmanFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
            throw new NotImplementedException();
        }
    }
}
