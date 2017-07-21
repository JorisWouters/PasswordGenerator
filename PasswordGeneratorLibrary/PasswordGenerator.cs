using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGeneratorLibrary
{
    public interface IPasswordGenerator : IDisposable
    {
        Salt GenerateSalt(int saltSize = 8);
        HashedPassword GenerateHash(string plainText);
        HashedPassword GenerateHash(string plainText, Salt salt);
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

        public Salt GenerateSalt(int saltSize = 8)
        {
            var saltBytes = new byte[saltSize];
            _rng.Value.GetNonZeroBytes(saltBytes);

            return new Salt { Content = Convert.ToBase64String(saltBytes) };
        }

        public HashedPassword GenerateHash(string plainText)
        {
            var salt = GenerateSalt();
            return GenerateHash(plainText, salt);
        }
                
        public HashedPassword GenerateHash(string plainText, Salt salt)
        {
            if (salt == null)
                throw new ArgumentNullException("salt");
            if (string.IsNullOrWhiteSpace(salt.Content))
                throw new ApplicationException("Salt is null or empty.");

            var saltBytes = TryFromBase64String(salt.Content);
            if (saltBytes == null)
                throw new FormatException("Illegal salt value.");

            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var plainTextWithSaltBytes = plainTextBytes.Concat(saltBytes).ToArray();

            var hashBytes = _sha.Value.ComputeHash(plainTextWithSaltBytes);
            var hashWithSaltBytes = hashBytes.Concat(saltBytes).ToArray();

            return new HashedPassword
            {
                Hash = Convert.ToBase64String(hashWithSaltBytes),
                Salt = salt
            };
        }

        private byte[] TryFromBase64String(string salt)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(salt))
                    return Convert.FromBase64String(salt);
            }
            catch(Exception)
            {
            }

            return null;
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
