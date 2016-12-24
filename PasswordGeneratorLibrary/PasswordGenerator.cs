using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGeneratorLibrary
{
    public interface IPasswordGenerator : IDisposable
    {
        string GenerateSalt(int saltSize = 8);
        string GenerateHash(string plainText, string salt);
    }

    public class PasswordGenerator : IPasswordGenerator
    {
        private LazyDisposable<RNGCryptoServiceProvider> _rng;
        private LazyDisposable<SHA512Managed> _sha;

        public PasswordGenerator()
        {
            _rng = new LazyDisposable<RNGCryptoServiceProvider>(() => new RNGCryptoServiceProvider());
            _sha = new LazyDisposable<SHA512Managed>(() => new SHA512Managed());
        }

        public string GenerateSalt(int saltSize = 8)
        {
            var saltBytes = new byte[saltSize];
            _rng.Value.GetNonZeroBytes(saltBytes);

            return Convert.ToBase64String(saltBytes);
        }
                
        public string GenerateHash(string plainText, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var plainTextWithSaltBytes = plainTextBytes.Concat(saltBytes).ToArray();

            var hashBytes = _sha.Value.ComputeHash(plainTextWithSaltBytes);
            var hashWithSaltBytes = hashBytes.Concat(saltBytes).ToArray();
            return Convert.ToBase64String(hashWithSaltBytes);
        }

        public void Dispose()
        {
            if (_rng != null)
            {
                _rng.Dispose();
                _rng = null;
            }

            if (_sha != null)
            {
                _sha.Dispose();
                _sha = null;
            }
        }
    }
}
