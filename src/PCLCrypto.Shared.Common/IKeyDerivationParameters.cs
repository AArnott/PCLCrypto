// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents parameters used when deriving a key.
    /// </summary>
    public interface IKeyDerivationParameters
    {
        /// <summary>
        /// Gets the number of iterations used to derive the key.
        /// </summary>
        /// <value>Iteration count.</value>
        int IterationCount { get; }

        /// <summary>
        /// Gets or sets the parameters used by the key derivation algorithm.
        /// </summary>
        /// <value>Buffer that contains the parameters.</value>
        byte[] KdfGenericBinary { get; set; }
    }
}
