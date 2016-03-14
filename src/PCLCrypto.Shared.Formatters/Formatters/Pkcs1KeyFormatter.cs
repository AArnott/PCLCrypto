// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// Encodes/decodes public keys and private keys in the PKCS#1 format
    /// (rsaPublicKey and rsaPrivateKey).
    /// </summary>
    /// <remarks>
    /// The format is described here: http://tools.ietf.org/html/rfc3447#page-46
    /// </remarks>
    internal class Pkcs1KeyFormatter : KeyFormatter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs1KeyFormatter"/> class.
        /// </summary>
        internal Pkcs1KeyFormatter()
        {
        }

        /// <summary>
        /// Reads a key from the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>
        /// The RSA Parameters of the key.
        /// </returns>
        protected override RSAParameters ReadCore(Stream stream)
        {
            var keyBlobElement = Asn.ReadAsn1Elements(stream).First();
            KeyFormatter.VerifyFormat(
                keyBlobElement.Class == Asn.BerClass.Universal &&
                keyBlobElement.PC == Asn.BerPC.Constructed &&
                keyBlobElement.Tag == Asn.BerTag.Sequence);

            stream = new MemoryStream(keyBlobElement.Content);
            var sequence = Asn.ReadAsn1Elements(stream).ToList();

            switch (sequence.Count)
            {
                case 2:
                    return new RSAParameters
                    {
                        Modulus = sequence[0].Content,
                        Exponent = sequence[1].Content,
                    };
                case 9:
                    KeyFormatter.VerifyFormat(sequence[0].Content.Length == 1 && sequence[0].Content[0] == 0, "Unsupported version.");
                    return new RSAParameters
                    {
                        Modulus = sequence[1].Content,
                        Exponent = sequence[2].Content,
                        D = sequence[3].Content,
                        P = sequence[4].Content,
                        Q = sequence[5].Content,
                        DP = sequence[6].Content,
                        DQ = sequence[7].Content,
                        InverseQ = sequence[8].Content,
                    };
                default:
                    throw KeyFormatter.FailFormat();
            }
        }

        /// <summary>
        /// Writes the core.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="value">The value.</param>
        protected override void WriteCore(Stream stream, RSAParameters value)
        {
            Requires.NotNull(stream, "stream");

            var sequence = new MemoryStream();

            if (KeyFormatter.HasPrivateKey(value))
            {
                // Only include the version element if this is a private key.
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, new byte[1]));
            }

            // Take care to always prepend a zero when an integer starts with a leading bit of 1,
            // since the ASN.1 spec is that integers are encoded as two's complement, and these integers
            // are always intended to be interpreted as positive.
            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.Modulus)));
            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.Exponent)));
            if (KeyFormatter.HasPrivateKey(value))
            {
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.D)));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.P)));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.Q)));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.DP)));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.DQ)));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, PrependLeadingZero(value.InverseQ)));
            }

            stream.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Constructed, Asn.BerTag.Sequence, sequence.ToArray()));
        }
    }
}
