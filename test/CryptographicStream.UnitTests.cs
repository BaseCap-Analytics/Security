// BaseCap Analytics licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;
using BaseCap.Security;
using BaseCap.Security.Test.Mocks;

namespace BaseCap.Security.Test
{
    public class CryptographicStreamUnitTests
    {
        [Fact]
        public async Task EnsureDisposeWorks()
        {
            FieldInfo f;
            byte[] key = EncryptionHelpers.CreateEncryptionKey();
            using (MemoryStream ms = new MemoryStream())
            {
                CryptographicStream s = await EncryptionHelpers.GetEncryptionStreamAsync(key, ms);
                f = s.GetType().GetField("_underlyingStream", BindingFlags.NonPublic | BindingFlags.Instance);
                Assert.NotNull(f.GetValue(s));
                s.Dispose();
                Assert.Null(f.GetValue(s));
            }
        }
    }
}
