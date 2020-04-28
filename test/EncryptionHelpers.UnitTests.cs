// BaseCap Analytics licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;
using BaseCap.Security.Test.Mocks;

namespace BaseCap.Security.Test
{
    public class EncryptionHelpersUnitTests
    {
        [Fact]
        public void CreateEncryptionKey_CreatesNonNullKey()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            Assert.NotNull(key);
            Assert.NotEmpty(key);
            Assert.False(Array.TrueForAll(key, k => k == 0));
        }

        [Fact]
        public void CreateEncryptionKey_CreatesDifferentKeysWithMultipleCalls()
        {
            byte[] key1 = EncryptionHelpers.CreateEncryptionKey();
            byte[] key2 = EncryptionHelpers.CreateEncryptionKey();
            Assert.NotNull(key1);
            Assert.NotEmpty(key1);
            Assert.NotEqual(key1, key2);
        }

        [Theory]
        [InlineData(128)]
        [InlineData(192)]
        [InlineData(256)]
        public void CreateEncryptionKey_WithValidSpecifiedKeySize_DoesNotCreateNullKey(int keySize)
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey(keySize);
            Assert.NotNull(key);
            Assert.NotEmpty(key);
            Assert.False(Array.TrueForAll(key, k => k == 0));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(64)]
        [InlineData(512)]
        public void CreateEncryptionKey_WithInvalidSpecifiedKeySize_Throws(int keySize)
        {
            Assert.Throws<CryptographicException>(() => EncryptionHelpers.CreateEncryptionKey(keySize));
        }

        [Fact]
        public async Task EncryptDataAsync_WithNullData_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.EncryptDataAsync(null, key));
        }

        [Fact]
        public async Task EncryptDataAsync_WithEmptyData_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.EncryptDataAsync(Array.Empty<byte>(), key));
        }

        [Fact]
        public async Task EncryptDataAsync_WithNullEncryptionKey_Throws()
        {
            byte[] data = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.EncryptDataAsync(data, null));
        }

        [Fact]
        public async Task EncryptDataAsync_WithEmptyEncryptionKey_Throws()
        {
            byte[] data = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.EncryptDataAsync(data, Array.Empty<byte>()));
        }

        [Fact]
        public async Task EncryptDataAsync_WithValidData_ReturnsEncryptedArray()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            byte[] data = new byte[128];
            new Random().NextBytes(data);
            byte[] result = await EncryptionHelpers.EncryptDataAsync(data, key);
            Assert.NotEqual(data, result);
        }

        [Fact]
        public async Task GetEncryptionStreamAsync_WithNullEncryptionKey_Throws()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.GetEncryptionStreamAsync(null, ms));
            }
        }

        [Fact]
        public async Task GetEncryptionStreamAsync_WithNullStream_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.GetEncryptionStreamAsync(key, null));
        }

        [Fact]
        public async Task GetEncryptionStreamAsync_WithEmptyEncryptionKey_Throws()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.GetEncryptionStreamAsync(Array.Empty<byte>(), ms));
            }
        }

        [Fact]
        public async Task GetEncryptionStreamAsync_WithNonWritableStream_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.GetEncryptionStreamAsync(key, new NonWritableStream()));
        }

        [Fact]
        public async Task GetEncryptionStreamAsync_WithValidData_WritesEncryptedData()
        {
            byte[] original = new byte[128];
            byte[] result;
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            new Random().NextBytes(original);
            using (MemoryStream ms = new MemoryStream())
            {
                using (Stream stream = await EncryptionHelpers.GetEncryptionStreamAsync(key, ms))
                {
                    await stream.WriteAsync(original, 0, original.Length);
                }

                result = ms.ToArray();
            }

            Assert.NotNull(result);
            Assert.NotEmpty(result);
            Assert.NotEqual(original, result);

            byte[] iv = new byte[16];
            Array.Copy(result, iv, 16);
            byte[] encrypted = new byte[result.Length - iv.Length];
            Array.Copy(result, encrypted, encrypted.Length);
            Assert.NotEqual(original, encrypted);
            Assert.Equal(result.Length, iv.Length + encrypted.Length);
        }

        [Fact]
        public async Task DecryptDataAsync_WithNullData_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.DecryptDataAsync(null, key));
        }

        [Fact]
        public async Task DecryptDataAsync_WithEmptyData_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.DecryptDataAsync(Array.Empty<byte>(), key));
        }

        [Fact]
        public async Task DecryptDataAsync_WithNullEncryptionKey_Throws()
        {
            byte[] data = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.DecryptDataAsync(data, null));
        }

        [Fact]
        public async Task DecryptDataAsync_WithEmptyEncryptionKey_Throws()
        {
            byte[] data = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.DecryptDataAsync(data, Array.Empty<byte>()));
        }

        [Fact]
        public async Task DecryptDataAsync_WithValidData_ReturnsEncryptedArray()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            byte[] data = new byte[128];
            byte[] encrypted = await EncryptionHelpers.EncryptDataAsync(data, key);
            byte[] result = await EncryptionHelpers.DecryptDataAsync(encrypted, key);
            Assert.Equal(data, result);
        }

        [Fact]
        public async Task GetDecryptionStreamAsync_WithNullEncryptionKey_Throws()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.GetDecryptionStreamAsync(null, ms));
            }
        }

        [Fact]
        public async Task GetDecryptionStreamAsync_WithNullStream_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await EncryptionHelpers.GetDecryptionStreamAsync(key, null));
        }

        [Fact]
        public async Task GetDecryptionStreamAsync_WithEmptyEncryptionKey_Throws()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.GetDecryptionStreamAsync(Array.Empty<byte>(), ms));
            }
        }

        [Fact]
        public async Task GetDecryptionStreamAsync_WithNonReadableStream_Throws()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await EncryptionHelpers.GetDecryptionStreamAsync(key, new NonReadableStream()));
        }

        [Fact]
        public async Task GetDecryptionStreamAsync_WithValidData_WritesDecryptedData()
        {
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            byte[] original = new byte[128];
            new Random().NextBytes(original);
            byte[] encrypted = await EncryptionHelpers.EncryptDataAsync(original, key);
            byte[] result;
            using (MemoryStream ms = new MemoryStream(encrypted))
            using (MemoryStream output = new MemoryStream())
            {
                using (Stream stream = await EncryptionHelpers.GetDecryptionStreamAsync(key, ms))
                {
                    await stream.CopyToAsync(output);
                }

                result = output.ToArray();
            }

            Assert.NotNull(result);
            Assert.NotEmpty(result);
            Assert.Equal(original, result);
        }
    }
}
