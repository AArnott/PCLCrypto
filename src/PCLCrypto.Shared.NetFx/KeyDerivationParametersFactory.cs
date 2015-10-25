// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="IKeyDerivationParametersFactory"/> interface.
    /// </summary>
    internal class KeyDerivationParametersFactory : IKeyDerivationParametersFactory
    {
        /// <inheritdoc />
        public IKeyDerivationParameters BuildForPbkdf2(byte[] pbkdf2Salt, int iterationCount)
        {
            return new KeyDerivationParameters(iterationCount, pbkdf2Salt);
        }

        /// <inheritdoc />
        public IKeyDerivationParameters BuildForSP800108(byte[] label, byte[] context)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public IKeyDerivationParameters BuildForSP80056a(byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// A .NET Framework implementation of the <see cref="IKeyDerivationParameters"/> interface.
        /// </summary>
        private class KeyDerivationParameters : IKeyDerivationParameters
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="KeyDerivationParameters"/> class.
            /// </summary>
            /// <param name="iterationCount">The iteration count.</param>
            /// <param name="kdfGenericBinary">The KDF generic binary.</param>
            internal KeyDerivationParameters(int iterationCount, byte[] kdfGenericBinary)
            {
                Requires.Range(iterationCount > 0, "iterationCount");
                Requires.NotNull(kdfGenericBinary, "kdfGenericBinary");

                this.IterationCount = iterationCount;
                this.KdfGenericBinary = kdfGenericBinary;
            }

            /// <inheritdoc />
            public int IterationCount { get; private set; }

            /// <inheritdoc />
            public byte[] KdfGenericBinary { get; set; }
        }
    }
}
