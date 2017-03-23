// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// The WinRT implementation of the <see cref="IMacAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class MacAlgorithmProviderFactory : IMacAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IMacAlgorithmProvider OpenAlgorithm(MacAlgorithm algorithm)
        {
            return new MacAlgorithmProvider(algorithm);
        }
    }
}
