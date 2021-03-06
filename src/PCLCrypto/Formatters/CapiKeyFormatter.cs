﻿// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Microsoft;

    /// <summary>
    /// Formats keys in the CAPI file format.
    /// This is the format used by RSACryptoServiceProvider.ExportCspBlob.
    /// </summary>
    public class CapiKeyFormatter : KeyFormatter
    {
        /// <summary>
        /// An identifier that the contents of this blob conform to the PUBLICKEYBLOB specification.
        /// </summary>
        private const byte PublicKeyBlobHeader = 0x06;

        /// <summary>
        /// An identifier that the contents of this blob conform to the PRIVATEKEYBLOB specification.
        /// </summary>
        private const byte PrivateKeyBlobHeader = 0x07;

        /// <summary>
        /// A byte indicating the blob version.
        /// </summary>
        private const byte CurrentBlobVersion = 0x02;

        /// <summary>
        /// A magic string: "RSA1".
        /// </summary>
        private const string PublicKeyMagicHeader = "RSA1"; // 0x31415352

        /// <summary>
        /// A magic string: "RSA2".
        /// </summary>
        private const string PrivateKeyMagicHeader = "RSA2"; // 0x32415352

        /// <summary>
        /// A magic header that indicates key exchange use.
        /// </summary>
        private const int KeySpecKeyExchange = 0x0000a400;

        /// <summary>
        /// Determines whether the specified RSA parameters
        /// can be represented in the CAPI format.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns><c>true</c> if CAPI is compatible with these parameters; <c>false</c> otherwise.</returns>
        public static bool IsCapiCompatible(RSAParameters parameters)
        {
            Requires.Argument(parameters.Modulus != null, nameof(parameters), Strings.PropertyXMustBeNonEmpty, nameof(RSAParameters.Modulus));

            // Only private keys have this restriction.
            if (!KeyFormatter.HasPrivateKey(parameters))
            {
                return true;
            }

            int halfModulusLength = (parameters.Modulus.Length + 1) / 2;

            // These are the same assertions that Windows crypto lib itself
            // follows when it returns 'bad data'.
            // CAPI's file format does not include lengths for parameters.
            // Instead it makes some assumptions about their relative lengths
            // which make it fundamentally incompatible with some private keys
            // generated by iOS.
            return
                halfModulusLength == parameters.P?.Length &&
                halfModulusLength == parameters.Q?.Length &&
                halfModulusLength == parameters.DP?.Length &&
                halfModulusLength == parameters.DQ?.Length &&
                halfModulusLength == parameters.InverseQ?.Length &&
                parameters.Modulus.Length == parameters.D?.Length;
        }

        /// <summary>
        /// Tries to add/remove leading zeros as necessary in an attempt to make the parameters CAPI compatible.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The modified set of parameters.</returns>
        /// <remarks>
        /// The original parameters and their buffers are not modified.
        /// </remarks>
        public static RSAParameters NegotiateSizes(RSAParameters parameters)
        {
            if (HasPrivateKey(parameters))
            {
                if (IsCapiCompatible(parameters))
                {
                    // Don't change a thing. Everything is perfect.
                    return parameters;
                }

                parameters.Modulus = TrimLeadingZero(parameters.Modulus);
                parameters.D = TrimLeadingZero(parameters.D);
                int keyLength = Math.Max(parameters.Modulus!.Length, parameters.D?.Length ?? 0);
                parameters.Modulus = TrimOrPadZeroToLength(parameters.Modulus, keyLength);
                parameters.D = TrimOrPadZeroToLength(parameters.D, keyLength);

                int halfKeyLength = (keyLength + 1) / 2;
                parameters.P = TrimOrPadZeroToLength(parameters.P, halfKeyLength);
                parameters.Q = TrimOrPadZeroToLength(parameters.Q, halfKeyLength);
                parameters.DP = TrimOrPadZeroToLength(parameters.DP, halfKeyLength);
                parameters.DQ = TrimOrPadZeroToLength(parameters.DQ, halfKeyLength);
                parameters.InverseQ = TrimOrPadZeroToLength(parameters.InverseQ, halfKeyLength);
            }
            else
            {
                parameters.Modulus = TrimLeadingZero(parameters.Modulus);
            }

            parameters.Exponent = TrimLeadingZero(parameters.Exponent);
            return parameters;
        }

        /// <summary>
        /// Throws an exception if the specified RSAParameters cannot be
        /// serialized in the CAPI format.
        /// </summary>
        /// <param name="parameters">The RSA parameters.</param>
        internal static void VerifyCapiCompatibleParameters(RSAParameters parameters)
        {
            try
            {
                KeyFormatter.VerifyFormat(IsCapiCompatible(parameters), "Private key parameters have lengths that are not supported by CAPI.");
            }
            catch (FormatException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
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
            var parameters = default(RSAParameters);

            using var reader = new BinaryReader(stream);

            bool hasPrivateKey;
            byte keyBlobHeader = reader.ReadByte();
            switch (keyBlobHeader)
            {
                case PrivateKeyBlobHeader:
                    hasPrivateKey = true;
                    break;
                case PublicKeyBlobHeader:
                    hasPrivateKey = false;
                    break;
                default:
                    throw KeyFormatter.FailFormat();
            }

            byte currentBlobVersion = reader.ReadByte();
            KeyFormatter.VerifyFormat(currentBlobVersion == CurrentBlobVersion);

            short reserved = reader.ReadInt16();
            KeyFormatter.VerifyFormat(reserved == 0);

            int keySpec = reader.ReadInt32();
            KeyFormatter.VerifyFormat(keySpec == KeySpecKeyExchange);

            string magicHeader = Encoding.UTF8.GetString(reader.ReadBytes(4), 0, 4);
            KeyFormatter.VerifyFormat(hasPrivateKey ? (magicHeader == PrivateKeyMagicHeader) : (magicHeader == PublicKeyMagicHeader));

            int bitlen = reader.ReadInt32();
            int bytelen = bitlen / 8;

            parameters.Exponent = ReadReversed(reader, 4);
            parameters.Modulus = ReadReversed(reader, bytelen);

            if (hasPrivateKey)
            {
                parameters.P = ReadReversed(reader, bytelen / 2);
                parameters.Q = ReadReversed(reader, bytelen / 2);
                parameters.DP = ReadReversed(reader, bytelen / 2);
                parameters.DQ = ReadReversed(reader, bytelen / 2);
                parameters.InverseQ = ReadReversed(reader, bytelen / 2);
                parameters.D = ReadReversed(reader, bytelen);
            }

            return parameters;
        }

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The RSA parameters of the key.</param>
        protected override void WriteCore(Stream stream, RSAParameters parameters)
        {
            if (!IsCapiCompatible(parameters))
            {
                // Try to get the RSA parameters to conform to CAPI's requirements.
                parameters = NegotiateSizes(parameters);
            }

            VerifyCapiCompatibleParameters(parameters);

            var writer = new BinaryWriter(stream);

            int bytelen = parameters.Modulus![0] == 0 // if high-order byte is zero, it's for sign bit; don't count in bit-size calculation
                ? parameters.Modulus.Length - 1
                : parameters.Modulus.Length;
            int bitlen = 8 * bytelen;

            writer.Write(KeyFormatter.HasPrivateKey(parameters) ? PrivateKeyBlobHeader : PublicKeyBlobHeader);
            writer.Write(CurrentBlobVersion);
            writer.Write((short)0); // reserved
            writer.Write(KeySpecKeyExchange);
            writer.Write(Encoding.UTF8.GetBytes(KeyFormatter.HasPrivateKey(parameters) ? PrivateKeyMagicHeader : PublicKeyMagicHeader));
            writer.Write(bitlen);

            // Ensure that the exponent occupies 4 bytes in the serialized stream,
            // even if in the parameters structure it does not.
            // We cannot use BitConverter.ToInt32 to help us do this because
            // its behavior varies based on the endianness of the platform,
            // yet RSAParameters is defined to always be Big Endian, and the
            // key blob format is defined to always be Little Endian, so we have to be careful.
            byte[] exponentPadding = new byte[4 - parameters.Exponent!.Length];
            WriteReversed(writer, parameters.Exponent);
            writer.Write(exponentPadding);

            // bytelen drops the sign byte if it is present (which is good)
            WriteReversed(writer, parameters.Modulus, bytelen);

            if (KeyFormatter.HasPrivateKey(parameters))
            {
                WriteReversed(writer, parameters.P!, bytelen / 2);
                WriteReversed(writer, parameters.Q!, bytelen / 2);
                WriteReversed(writer, parameters.DP!, bytelen / 2);
                WriteReversed(writer, parameters.DQ!, bytelen / 2);
                WriteReversed(writer, parameters.InverseQ!, bytelen / 2);
                WriteReversed(writer, parameters.D!, bytelen);
            }

            writer.Flush();
            writer.Dispose();
        }

        /// <summary>
        /// Writes a buffer to a stream in reverse byte order.
        /// </summary>
        /// <param name="writer">The writer to copy <paramref name="data"/> to.</param>
        /// <param name="data">The data to copy, reverse and write to the stream. This buffer instance is not modified.</param>
        /// <param name="length">The number of bytes to write to the stream after the order reversal. A negative value means to copy the entire buffer.</param>
        private static void WriteReversed(BinaryWriter writer, byte[] data, int length = -1)
        {
            writer.Write(CopyAndReverse(data), 0, length < 0 ? data.Length : length);
        }

        /// <summary>
        /// Reads data from a stream and reverses the byte order.
        /// </summary>
        /// <param name="reader">The reader to use to read from the stream.</param>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>The buffer read from the stream, after reversing its byte order.</returns>
        private static byte[] ReadReversed(BinaryReader reader, int length)
        {
            byte[] buffer = reader.ReadBytes(length);
            Array.Reverse(buffer);
            return buffer;
        }
    }
}
