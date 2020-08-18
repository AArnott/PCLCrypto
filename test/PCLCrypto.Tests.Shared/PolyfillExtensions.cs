// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Buffers;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft;

#if NETFRAMEWORK || WINDOWS_UWP

    internal static class PolyfillExtensions
    {
        /// <summary>
        /// Reads from the stream into a memory buffer.
        /// </summary>
        /// <param name="stream">The stream to read from.</param>
        /// <param name="buffer">The buffer to read directly into.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The number of bytes actually read.</returns>
        /// <devremarks>
        /// This method shamelessly copied from the .NET Core 2.1 Stream class: https://github.com/dotnet/coreclr/blob/a113b1c803783c9d64f1f0e946ff9a853e3bc140/src/System.Private.CoreLib/shared/System/IO/Stream.cs#L366-L391.
        /// </devremarks>
        internal static ValueTask<int> ReadAsync(this Stream stream, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Requires.NotNull(stream, nameof(stream));

            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array))
            {
                return new ValueTask<int>(stream.ReadAsync(array.Array, array.Offset, array.Count, cancellationToken));
            }
            else
            {
                byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
                return FinishReadAsync(stream.ReadAsync(sharedBuffer, 0, buffer.Length, cancellationToken), sharedBuffer, buffer);

                async ValueTask<int> FinishReadAsync(Task<int> readTask, byte[] localBuffer, Memory<byte> localDestination)
                {
                    try
                    {
                        int result = await readTask.ConfigureAwait(false);
                        new Span<byte>(localBuffer, 0, result).CopyTo(localDestination.Span);
                        return result;
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(localBuffer);
                    }
                }
            }
        }

        /// <summary>
        /// Writes to a stream from a memory buffer.
        /// </summary>
        /// <param name="stream">The stream to write to.</param>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A task that indicates when the write operation is complete.</returns>
        /// <devremarks>
        /// This method shamelessly copied from the .NET Core 2.1 Stream class: https://github.com/dotnet/coreclr/blob/a113b1c803783c9d64f1f0e946ff9a853e3bc140/src/System.Private.CoreLib/shared/System/IO/Stream.cs#L672-L696.
        /// </devremarks>
        internal static ValueTask WriteAsync(this Stream stream, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Requires.NotNull(stream, nameof(stream));

            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array))
            {
                return new ValueTask(stream.WriteAsync(array.Array, array.Offset, array.Count, cancellationToken));
            }
            else
            {
                byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
                buffer.Span.CopyTo(sharedBuffer);
                return new ValueTask(FinishWriteAsync(stream.WriteAsync(sharedBuffer, 0, buffer.Length, cancellationToken), sharedBuffer));
            }

            async Task FinishWriteAsync(Task writeTask, byte[] localBuffer)
            {
                try
                {
                    await writeTask.ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(localBuffer);
                }
            }
        }
    }

#endif
}
