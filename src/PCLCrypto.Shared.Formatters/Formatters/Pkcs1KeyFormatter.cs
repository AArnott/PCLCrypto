//-----------------------------------------------------------------------
// <copyright file="Pkcs1KeyFormatter.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
        /// If set to <c>true</c> certain parameters will have a 0x00 prepended to their binary representations: Modulus, P, Q, DP, InverseQ.
        /// </summary>
        private readonly bool prependLeadingZeroOnCertainElements;

        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs1KeyFormatter"/> class.
        /// </summary>
        /// <param name="prependLeadingZeroOnCertainElements">If set to <c>true</c> certain parameters will have a 0x00 prepended to their binary representations: Modulus, P, Q, DP, InverseQ.</param>
        internal Pkcs1KeyFormatter(bool prependLeadingZeroOnCertainElements = false)
        {
            this.prependLeadingZeroOnCertainElements = prependLeadingZeroOnCertainElements;
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

            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, this.prependLeadingZeroOnCertainElements ? PrependLeadingZero(value.Modulus) : value.Modulus));
            sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.Exponent));
            if (KeyFormatter.HasPrivateKey(value))
            {
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.D));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, this.prependLeadingZeroOnCertainElements ? PrependLeadingZero(value.P) : value.P));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, this.prependLeadingZeroOnCertainElements ? PrependLeadingZero(value.Q) : value.Q));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, this.prependLeadingZeroOnCertainElements ? PrependLeadingZero(value.DP) : value.DP));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, value.DQ));
                sequence.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Primitive, Asn.BerTag.Integer, this.prependLeadingZeroOnCertainElements ? PrependLeadingZero(value.InverseQ) : value.InverseQ));
            }

            stream.WriteAsn1Element(new Asn.DataElement(Asn.BerClass.Universal, Asn.BerPC.Constructed, Asn.BerTag.Sequence, sequence.ToArray()));
        }
    }
}
