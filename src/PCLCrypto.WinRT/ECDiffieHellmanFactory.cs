//-----------------------------------------------------------------------
// <copyright file="ECDiffieHellmanFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// The WinRT implementation of the <see cref="IECDiffieHellmanFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanFactory : IECDiffieHellmanFactory
    {
        /// <inheritdoc />
        public IECDiffieHellman Create()
        {
            throw new NotSupportedException();
        }
    }
}
