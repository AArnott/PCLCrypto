// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#pragma warning disable SA1118 // ParameterMustNotSpanMultipleLines

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Serializes RSA keys in the PKCS8 PrivateKeyInfo format.
    /// </summary>
    /// <remarks>
    /// Spec found at: http://tools.ietf.org/html/rfc5208#page-3
    /// </remarks>
    internal class Pkcs8KeyFormatter : KeyFormatter
    {
        /// <summary>
        /// Reads a key from the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>
        /// The RSA Parameters of the key.
        /// </returns>
        protected override RSAParameters ReadCore(Stream stream)
        {
            var universalConstructedSequence = stream.ReadAsn1Elements().Single();
            var sequence = Asn.ReadAsn1Elements(universalConstructedSequence.Content).ToList();
            KeyFormatter.VerifyFormat(sequence[0].Content.Length == 1 && sequence[0].Content[0] == 0x00, "Unrecognized version.");
            Asn.DataElement oid = Asn.ReadAsn1Elements(sequence[1].Content).First();
            KeyFormatter.VerifyFormat(X509SubjectPublicKeyInfoFormatter.BufferEqual(oid.Content, Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier), "Unrecognized object identifier.");
            return KeyFormatter.Pkcs1.Read(sequence[2].Content);
        }

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The RSA parameters of the key.</param>
        protected override void WriteCore(Stream stream, RSAParameters parameters)
        {
            var rootElement = new Asn.DataElement(
                Asn.BerClass.Universal,
                Asn.BerPC.Constructed,
                Asn.BerTag.Sequence,
                new Asn.DataElement( // Version 0
                    Asn.BerClass.Universal,
                    Asn.BerPC.Primitive,
                    Asn.BerTag.Integer,
                    new byte[] { 0x00 }),
                new Asn.DataElement(
                    Asn.BerClass.Universal,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.Sequence,
                    new Asn.DataElement( // privateKeyAlgorithm
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.ObjectIdentifier,
                        Pkcs1KeyFormatter.RsaEncryptionObjectIdentifier),
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Primitive,
                        Asn.BerTag.Null,
                        new byte[0])),
                new Asn.DataElement( // rsaPrivateKey
                    Asn.BerClass.Universal,
                    Asn.BerPC.Primitive,
                    Asn.BerTag.OctetString,
                    KeyFormatter.Pkcs1.Write(parameters, HasPrivateKey(parameters))),
                new Asn.DataElement(
                    Asn.BerClass.ContextSpecific,
                    Asn.BerPC.Constructed,
                    Asn.BerTag.EndOfContent,
                    new Asn.DataElement(
                        Asn.BerClass.Universal,
                        Asn.BerPC.Constructed,
                        Asn.BerTag.Sequence,
                        new Asn.DataElement(
                            Asn.BerClass.Universal,
                            Asn.BerPC.Primitive,
                            Asn.BerTag.ObjectIdentifier,
                            new byte[] { 0x55, 0x1d, 0x0f }),
                        new Asn.DataElement(
                            Asn.BerClass.Universal,
                            Asn.BerPC.Constructed,
                            Asn.BerTag.SetAndSetOf,
                            new Asn.DataElement(
                                Asn.BerClass.Universal,
                                Asn.BerPC.Primitive,
                                Asn.BerTag.BitString,
                                new byte[] { 0x00, 0x10 })))));

            Asn.WriteAsn1Element(stream, rootElement);
        }
    }
}
