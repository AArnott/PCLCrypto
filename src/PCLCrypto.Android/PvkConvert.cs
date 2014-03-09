//-----------------------------------------------------------------------
// <copyright file="PvkConvert.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
//     This file contains a derivative work from the file referred to from:
//     http://www.jensign.com/JavaScience/PvkConvert/
//     Applicable copyrights from original authors may apply.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Android.App;
    using Android.Content;
    using Android.OS;
    using Android.Runtime;
    using Android.Views;
    using Android.Widget;
    using Java.IO;
    using Java.Lang;
    using Java.Math;
    using Java.Security;
    using Java.Security.Interfaces;
    using Java.Security.Spec;
    using Validation;

    /// <summary>
    /// Key formatting utilities.
    /// </summary>
    internal static class PvkConvert
    {
        /// <summary>
        /// An identifier that the contents of this blob conform to the PUBLICKEYBLOB specification.
        /// </summary>
        private const byte PUBLICKEYBLOB = 0x06;

        /// <summary>
        /// An identifier that the contents of this blob conform to the PRIVATEKEYBLOB specification.
        /// </summary>
        private const byte PRIVATEKEYBLOB = 0x07;

        /// <summary>
        /// A byte indicating the blob version.
        /// </summary>
        private const byte CURBLOBVERSION = 0x02;

        /// <summary>
        /// A reserved 2-byte value of 0.
        /// </summary>
        private const short RESERVED = 0x0000;

        /// <summary>
        /// A magic string: "RSA1"
        /// </summary>
        private const string MAGIC1 = "RSA1"; // 0x31415352

        /// <summary>
        /// A magic string: "RSA2"
        /// </summary>
        private const string MAGIC2 = "RSA2"; // 0x32415352

        /// <summary>
        /// A map of key specs to their values in the blob.
        /// </summary>
        private static readonly IReadOnlyDictionary<KeySpec, int> KEYSPECS = new Dictionary<KeySpec, int>
        {
            { KeySpec.KeyExchange, 0x0000a400 },
            { KeySpec.Signature, 0x00002400 },
        };

        /// <summary>
        /// The purpose of key use.
        /// </summary>
        internal enum KeySpec
        {
            /// <summary>
            /// Key exchange.
            /// </summary>
            KeyExchange = 1,

            /// <summary>
            /// Signing data.
            /// </summary>
            Signature = 2,
        }

        /// <summary>
        /// Writes out a private key as a PRIVATEKEYBLOB (<see cref="CryptographicPrivateKeyBlobType.Capi1PrivateKey"/>).
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="keySpec">The keyspec.</param>
        /// <returns>A buffer containing the PRIVATEKEYBLOB.</returns>
        internal static byte[] GetEncodedPrivateKeyBlob(this IPrivateKey privateKey, KeySpec keySpec = KeySpec.KeyExchange)
        {
            Requires.NotNull(privateKey, "privateKey");

            var ms = new MemoryStream();
            WritePrivateKeyBlob(ms, privateKey, keySpec);
            return ms.ToArray();
        }

        /// <summary>
        /// Writes out a private key as a PRIVATEKEYBLOB (<see cref="CryptographicPrivateKeyBlobType.Capi1PrivateKey"/>).
        /// </summary>
        /// <param name="stream">The stream to write the blob to.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="keySpec">The keyspec.</param>
        internal static void WritePrivateKeyBlob(this Stream stream, IPrivateKey privateKey, KeySpec keySpec = KeySpec.KeyExchange)
        {
            Requires.NotNull(stream, "stream");
            Requires.NotNull(privateKey, "privateKey");

            var writer = new BinaryWriter(stream);

            IRSAPrivateCrtKey pvkKey = privateKey.JavaCast<IRSAPrivateCrtKey>();

            BigInteger mod = pvkKey.Modulus;
            byte[] modulus = mod.ToByteArray();

            int bytelen = modulus[0] == 0     // if high-order byte is zero, it's for sign bit; don't count in bit-size calculation
                ? modulus.Length - 1
                : modulus.Length;
            int bitlen = 8 * bytelen;

            writer.Write(PRIVATEKEYBLOB);
            writer.Write(CURBLOBVERSION);
            writer.Write(RESERVED);
            writer.WriteLittleEndian(KEYSPECS[keySpec]);
            writer.Write(Encoding.ASCII.GetBytes(MAGIC2));
            writer.WriteLittleEndian(bitlen);
            writer.WriteLittleEndian(pvkKey.PublicExponent.IntValue());

            // note that modulus may contain an extra zero byte (highest order byte after reversing)
            // specifying bytelen bytes to write will drop high-order zero byte
            byte[] data = modulus;
            ReverseMemory(data); // Switches to Little Endian byte order.
            writer.Write(data, 0, bytelen);

            data = pvkKey.PrimeP.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeQ.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeExponentP.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen / 2);

            data = pvkKey.PrimeExponentQ.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen / 2);

            data = pvkKey.CrtCoefficient.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen / 2);

            data = pvkKey.PrivateExponent.ToByteArray();
            ReverseMemory(data);
            writer.Write(data, 0, bytelen);

            writer.Flush();
            writer.Close();
        }

        /// <summary>
        /// Writes an integer to an output stream in Little Endian format.
        /// </summary>
        /// <param name="writer">The binary writer.</param>
        /// <param name="value">The number to emit.</param>
        private static void WriteLittleEndian(this BinaryWriter writer, int value)
        {
            Requires.NotNull(writer, "output");

            writer.Write((byte)(value & 0xFF));
            writer.Write((byte)((value >> 8) & 0xFF));
            writer.Write((byte)((value >> 16) & 0xFF));
            writer.Write((byte)((value >> 24) & 0xFF));
        }

        /// <summary>
        /// Performs a byte-for-byte order reversal of a memory buffer.
        /// </summary>
        /// <param name="buffer">The buffer the reverse.</param>
        private static void ReverseMemory(byte[] buffer)
        {
            Requires.NotNull(buffer, "buffer");

            int length = buffer.Length;
            for (int i = 0; i < length / 2; i++)
            {
                byte b = buffer[i];
                buffer[i] = buffer[length - i - 1];
                buffer[length - i - 1] = b;
            }
        }
    }
}