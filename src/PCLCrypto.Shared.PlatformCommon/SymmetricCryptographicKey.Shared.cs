// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;

    /// <content>
    /// The common property getters.
    /// </content>
    internal partial class SymmetricCryptographicKey
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

        /// <summary>
        /// Gets a value indicating whether multiple calls to encrypt/decrypt a block size
        /// input is equivalent to the same operation but with all the input at once.
        /// </summary>
        private bool CanStreamAcrossTopLevelCipherOperations
            => this.Padding == SymmetricAlgorithmPadding.None && !this.Mode.IsAuthenticated();
    }
}
