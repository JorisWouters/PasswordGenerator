using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGeneratorLibrary
{
    public interface IPasswordGenerator
    {
        string GenerateSalt(int saltSize = 8);
        string GenerateHash(string plainText, string salt);
    }

    public class PasswordGenerator : IPasswordGenerator
    {
        public string GenerateSalt(int saltSize = 8)
        {
            var saltBytes = new byte[saltSize];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetNonZeroBytes(saltBytes);

            return Convert.ToBase64String(saltBytes);
        }
                
        public string GenerateHash(string plainText, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var plainTextWithSaltBytes = plainTextBytes.Concat(saltBytes).ToArray();

            using (var hasher = new SHA512Managed())
            {
                var hashBytes = hasher.ComputeHash(plainTextWithSaltBytes);
                var hashWithSaltBytes = hashBytes.Concat(saltBytes).ToArray();
                return Convert.ToBase64String(hashWithSaltBytes);
            }
        }
    }
}
