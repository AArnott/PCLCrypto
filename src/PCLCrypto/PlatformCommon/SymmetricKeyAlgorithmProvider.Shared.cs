// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <content>
    /// The common property getters.
    /// </content>
    internal partial class SymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Gets the algorithm used by this instance.
        /// </summary>
        public SymmetricAlgorithmName Name { get; }

        /// <summary>
        /// Gets the mode used by this instance.
        /// </summary>
        public SymmetricAlgorithmMode Mode { get; }

        /// <summary>
        /// Gets the padding used by this instance.
        /// </summary>
        public SymmetricAlgorithmPadding Padding { get; }
    }
}
