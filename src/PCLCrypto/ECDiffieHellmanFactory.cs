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
    /// The .NET Core implementation of <see cref="IECDiffieHellmanFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanFactory : IECDiffieHellmanFactory
    {
        /// <inheritdoc />
        public IECDiffieHellman Create()
        {
#if NETSTANDARD2_0
            throw new NotImplementedByReferenceAssemblyException();
#elif WINDOWS_UWP
            throw new PlatformNotSupportedException();
#else
            Platform.ECDiffieHellman platformAlgorithm;
            try
            {
                platformAlgorithm = Platform.ECDiffieHellman.Create();
            }
            catch (NotImplementedException ex)
            {
                throw new PlatformNotSupportedException("ECDiffieHellman.Create() threw an exception.", ex);
            }

            return new ECDiffieHellman(platformAlgorithm);
#endif
        }
    }
}
