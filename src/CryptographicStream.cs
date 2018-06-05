// BaseCap Analytics licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace BaseCap.Security
{
    /// <summary>
    /// A self-encrypting and self-decrypting stream
    /// </summary>
    public class CryptographicStream : Stream, IDisposable
    {
        // Keep the encryption classes internally so we can cleanup and be a good citizen.
        // All we really do is redirect to the underlying stream.
        private SymmetricAlgorithm _algorithm;
        private ICryptoTransform _transform;
        private CryptoStream _underlyingStream;

        public override bool CanRead => _underlyingStream.CanRead;

        public override bool CanSeek => _underlyingStream.CanSeek;

        public override bool CanWrite => _underlyingStream.CanWrite;

        public override long Length => _underlyingStream.Length;

        public override long Position { get => _underlyingStream.Position; set => _underlyingStream.Position = value; }


        internal CryptographicStream(SymmetricAlgorithm algorithm, ICryptoTransform transform, CryptoStream stream)
        {
            _algorithm = algorithm;
            _transform = transform;
            _underlyingStream = stream;
        }

        protected override void Dispose(bool disposing)
        {
            if (_underlyingStream != null)
            {
                if (disposing)
                {
                    _underlyingStream.Flush();
                    _underlyingStream.Dispose();
                    _transform.Dispose();
                    _algorithm.Dispose();
                }

                _underlyingStream = null;
                _transform = null;
                _algorithm = null;
            }
        }

        public override void Flush()
        {
            _underlyingStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _underlyingStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _underlyingStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _underlyingStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _underlyingStream.Write(buffer, offset, count);
        }

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return _underlyingStream.CopyToAsync(destination, bufferSize, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _underlyingStream.FlushAsync();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _underlyingStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override int ReadByte()
        {
            return _underlyingStream.ReadByte();
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _underlyingStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override void WriteByte(byte value)
        {
            _underlyingStream.WriteByte(value);
        }
    }
}
