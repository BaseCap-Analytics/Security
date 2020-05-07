// BaseCap Analytics licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BaseCap.Security
{
    /// <summary>
    /// Helper functions to provide easy encryption and easy decryption
    /// </summary>
    public static class EncryptionHelpers
    {
        private const int IV_SIZE_IN_BYTES = 16;
        private const int DEFAULT_BLOCK_SIZE = 128;

        private static SymmetricAlgorithm GetAlgorithm()
        {
            SymmetricAlgorithm alg = Aes.Create();
            return alg;
        }

        private static SymmetricAlgorithm CreateAlgorithm(byte[] encryptionKey)
        {
            SymmetricAlgorithm alg = GetAlgorithm();
            alg.Key = encryptionKey;
            alg.BlockSize = DEFAULT_BLOCK_SIZE;
            return alg;
        }

        /// <summary>
        /// Generates a new, secure encryption key
        /// </summary>
        /// <returns>Returns an array of bytes that can be used as an encryption key</returns>
        public static byte[] CreateEncryptionKey()
        {
            byte[] key;
            using (SymmetricAlgorithm alg = GetAlgorithm())
            {
                alg.GenerateKey();
                key = alg.Key;
            }

            return key;
        }

        /// <summary>
        /// Generates a new, secure encryption key
        /// </summary>
        /// <param name="keySize">The size of the key to create</param>
        /// <returns>Returns an array of bytes that can be used as an encryption key</returns>
        public static byte[] CreateEncryptionKey(int keySize)
        {
            byte[] key;
            using (SymmetricAlgorithm alg = GetAlgorithm())
            {
                alg.KeySize = keySize;
                alg.GenerateKey();
                key = alg.Key;
            }

            return key;
        }

        /// <summary>
        /// Encrypts an array of data and returns the encrypted array
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="encryptionKey">The secret value to encrypt the data with</param>
        /// <returns>Returns an array of encrypted bytes</returns>
        public static async Task<byte[]> EncryptDataAsync(byte[] data, byte[] encryptionKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length < 1) throw new ArgumentOutOfRangeException(nameof(data.Length));
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey));

            byte[] iv;
            byte[] result;
            using (SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey))
            {
                alg.GenerateIV();
                iv = alg.IV;
                using (ICryptoTransform encryptor = alg.CreateEncryptor(encryptionKey, iv))
                using (MemoryStream ms = new MemoryStream(data.Length + IV_SIZE_IN_BYTES))
                {
                    using (CryptoStream crypto = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        await ms.WriteAsync(iv, 0, iv.Length);
                        await crypto.WriteAsync(data, 0, data.Length);
                    }

                    result = ms.ToArray();
                }
            }

            return result;
        }

        /// <summary>
        /// Encrypts data and returns the encrypted array
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="encryptionKey">The secret value to encrypt the data with</param>
        /// <returns>Returns an array of encrypted bytes</returns>
        public static async Task<byte[]> EncryptDataAsync(ReadOnlyMemory<byte> data, byte[] encryptionKey)
        {
            if (data.Length < 1) throw new ArgumentOutOfRangeException(nameof(data.Length));
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey));

            byte[] result;
            using (SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey))
            {
                alg.GenerateIV();
                byte[] iv = alg.IV;
                using (ICryptoTransform encryptor = alg.CreateEncryptor(encryptionKey, iv))
                using (MemoryStream ms = new MemoryStream(data.Length + IV_SIZE_IN_BYTES))
                {
                    using (CryptoStream crypto = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        await ms.WriteAsync(iv, 0, iv.Length);
                        await crypto.WriteAsync(data);
                    }

                    result = ms.ToArray();
                }
            }

            return result;
        }

        /// <summary>
        /// Creates a stream to write raw data to that will be encrypted on the fly
        /// </summary>
        /// <param name="encryptionKey">The secret key used to encrypt the data</param>
        /// <param name="underlying">The underlying stream to write the encrypted data to</param>
        /// <returns>Returns a <see cref="CryptographicStream"> object to encrypt data on the fly</returns>
        public static async Task<CryptographicStream> GetEncryptionStreamAsync(byte[] encryptionKey, Stream underlying)
        {
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey.Length));
            if (underlying == null) throw new ArgumentNullException(nameof(underlying));
            if (underlying.CanWrite == false) throw new ArgumentOutOfRangeException(nameof(underlying.CanWrite));

            // Create the algorithm to encrypt and generate a unique initialization vector
            SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey);
            alg.GenerateIV();

            // Create the encryptor and write the IV to the stream unencrypted
            byte[] iv = alg.IV;
            ICryptoTransform encryptor = alg.CreateEncryptor(encryptionKey, iv);
            await underlying.WriteAsync(iv, 0, iv.Length);

            CryptoStream crypto = new CryptoStream(underlying, encryptor, CryptoStreamMode.Write);
            return new CryptographicStream(alg, encryptor, crypto);
        }

        /// <summary>
        /// Decrypts an array of data and returns the decrypted array
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="encryptionKey">The secret value to decrypt the data with</param>
        /// <returns>Returns an array of decrypted bytes</returns>
        public static async Task<byte[]> DecryptDataAsync(byte[] data, byte[] encryptionKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length < 1) throw new ArgumentOutOfRangeException(nameof(data.Length));
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey));

            byte[] result;
            byte[] iv = new byte[IV_SIZE_IN_BYTES];
            Array.Copy(data, iv, iv.Length);

            using (SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey))
            {
                // Set the initialization vector
                alg.IV = iv;

                using (ICryptoTransform decryptor = alg.CreateDecryptor(encryptionKey, iv))
                using (MemoryStream decrypted = new MemoryStream())
                {
                    using (MemoryStream encrypted = new MemoryStream(data, IV_SIZE_IN_BYTES, data.Length - IV_SIZE_IN_BYTES))
                    using (CryptoStream crypto = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
                    {
                        await crypto.CopyToAsync(decrypted);
                    }

                    result = decrypted.ToArray();
                }
            }

            return result;
        }

        /// <summary>
        /// Decrypts a Span of data and returns the decrypted data
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="encryptionKey">The secret value to decrypt the data with</param>
        /// <returns>Returns an array of decrypted bytes</returns>
        public static async Task<byte[]> DecryptDataAsync(ReadOnlyMemory<byte> data, byte[] encryptionKey)
        {
            if (data.Length < 1) throw new ArgumentOutOfRangeException(nameof(data.Length));
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey));

            byte[] result;
            using (SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey))
            {
                // Set the initialization vector
                alg.IV = data.Slice(0, IV_SIZE_IN_BYTES).ToArray();

                using (ICryptoTransform decryptor = alg.CreateDecryptor(encryptionKey, alg.IV))
                using (MemoryStream decrypted = new MemoryStream())
                {
                    using (MemoryStream encrypted = new MemoryStream())
                    {
                        await encrypted.WriteAsync(data.Slice(IV_SIZE_IN_BYTES)).ConfigureAwait(false);
                        encrypted.Seek(0, SeekOrigin.Begin);

                        using (CryptoStream crypto = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
                        {
                            await crypto.CopyToAsync(decrypted);
                        }
                    }

                    result = decrypted.ToArray();
                }
            }

            return result;
        }

        /// <summary>
        /// Creates a stream to read encrypted data from that will be decrypted on the fly
        /// </summary>
        /// <param name="encryptionKey">The secret key used to decrypt the data</param>
        /// <param name="underlying">The underlying stream to read the encrypted data from</param>
        /// <returns>Returns a <see cref="CryptographicStream"> object to decrypt data from on the fly</returns>
        public static async Task<CryptographicStream> GetDecryptionStreamAsync(byte[] encryptionKey, Stream underlying)
        {
            if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
            if (encryptionKey.Length < 1) throw new ArgumentOutOfRangeException(nameof(encryptionKey.Length));
            if (underlying == null) throw new ArgumentNullException(nameof(underlying));
            if (underlying.CanRead == false) throw new ArgumentOutOfRangeException(nameof(underlying.CanRead));

            // Get the original IV from the stream
            byte[] iv = new byte[IV_SIZE_IN_BYTES];
            await underlying.ReadAsync(iv, 0, iv.Length);

            // Create the algorithm to decrypt the data
            SymmetricAlgorithm alg = CreateAlgorithm(encryptionKey);
            alg.IV = iv;

            ICryptoTransform decryptor = alg.CreateDecryptor(encryptionKey, iv);
            CryptoStream crypto = new CryptoStream(underlying, decryptor, CryptoStreamMode.Read);
            return new CryptographicStream(alg, decryptor, crypto);
        }
    }
}
