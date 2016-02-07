// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#pragma warning disable SA1118 // ParameterMustNotSpanMultipleLines

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// Encodes/decodes public keys in the X.509 subject public key info format.
    /// </summary>
    internal class X509SubjectPublicKeyInfoFormatter : KeyFormatter
    {
        /// <summary>
        /// Reads a key from the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>
        /// The RSA Parameters of the key.
        /// </returns>
        /// <exception cref="System.ArgumentException">
        /// Unexpected format.
        /// or
        /// Unexpected format.
        /// or
        /// Unexpected algorithm.
        /// or
        /// Unexpected format.
        /// </exception>
        protected override RSAParameters ReadCore(Stream stream)
        {
            var sequence = stream.ReadAsn1Elements().First();
            if (sequence.Class != Asn.BerClass.Universal || sequence.PC != Asn.BerPC.Constructed || sequence.Tag != Asn.BerTag.Sequence)
            {
                throw new ArgumentException("Unexpected format.");
            }

            var elements = Asn.ReadAsn1Elements(sequence.Content).ToList();
            if (elements.Count != 2 || elements[0].Class != Asn.BerClass.Universal || elements[0].PC != Asn.BerPC.Constructed || elements[0].Tag != Asn.BerTag.Sequence)
            {
                throw new ArgumentException("Unexpected format.");
            }

            var oid = Asn.ReadAsn1Elements(elements[0].Content).First();
            if (!KeyFormatter.BufferEqual(Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier, oid.Content))
            {
                throw new ArgumentException("Unexpected algorithm.");
            }

            if (elements[1].Class != Asn.BerClass.Universal || elements[1].PC != Asn.BerPC.Primitive || elements[1].Tag != Asn.BerTag.BitString || elements[1].Content[0] != 0)
            {
                throw new ArgumentException("Unexpected format.");
            }

            byte[] rsaPublicKey = TrimLeadingZero(elements[1].Content);
            return KeyFormatter.PublicKeyFilter(KeyFormatter.Pkcs1.Read(rsaPublicKey));
        }

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The RSA parameters of the key.</param>
        protected override void WriteCore(Stream stream, RSAParameters parameters)
        {
            Requires.NotNull(stream, "stream");

            var rootElement = new Asn.DataElement(
                Asn.BerClass.Universal,
                Asn.BerPC.Constructed,
                Asn.BerTag.Sequence,
                new Asn.DataElement(
                    Asn.BerClass.Universal,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.Sequence,
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.ObjectIdentifier,
                        Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier),
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.Null,
                        new byte[0])),
                new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.BitString,
                        PrependLeadingZero(KeyFormatter.Pkcs1.Write(parameters, includePrivateKey: false), alwaysPrependZero: true)));
            stream.WriteAsn1Element(rootElement);
        }
    }
}
