// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// A factory for constructing parameters for deriving a key.
    /// </summary>
    public interface IKeyDerivationParametersFactory
    {
        /// <summary>
        /// Creates a KeyDerivationParameters object for use in the password-based key
        /// derivation function 2 (PBKDF2).
        /// </summary>
        /// <param name="pbkdf2Salt">The salt, a random or pseudorandom value to be combined with the password
        /// in multiple iterations. A salt is used to increase entropy above what can
        /// be obtained from using a password alone.</param>
        /// <param name="iterationCount">Number of iterations to be used to derive a key.</param>
        /// <returns>
        /// Refers to the parameters used during key derivation.
        /// </returns>
        IKeyDerivationParameters BuildForPbkdf2(byte[] pbkdf2Salt, int iterationCount);

        /// <summary>
        /// Creates a KeyDerivationParameters object for use in a counter mode, hash-based
        /// message authentication code (HMAC) key derivation function.
        /// </summary>
        /// <param name="label">Buffer that specifies the purpose for the derived keying material.</param>
        /// <param name="context">Buffer that specifies information related to the derived keying material.
        /// For example, the context can identify the parties who are deriving the keying
        /// material and, optionally, a nonce known by the parties.</param>
        /// <returns>
        /// Refers to the parameters used during key derivation.
        /// </returns>
        IKeyDerivationParameters BuildForSP800108(byte[] label, byte[] context);

        /// <summary>
        /// Creates a KeyDerivationParameters object for use in the SP800-56A key derivation
        /// function.
        /// </summary>
        /// <param name="algorithmId">Specifies the intended purpose of the derived key.</param>
        /// <param name="partyUInfo">Contains public information contributed by the initiator.</param>
        /// <param name="partyVInfo">Contains public information contributed by the responder.</param>
        /// <param name="suppPubInfo">Contains public information known to both initiator and responder.</param>
        /// <param name="suppPrivInfo">Contains private information known to both initiator and responder, such
        /// as a shared secret.</param>
        /// <returns>
        /// Refers to the parameters used during key derivation.
        /// </returns>
        IKeyDerivationParameters BuildForSP80056a(byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo);
    }
}
