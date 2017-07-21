using FluentAssertions;
using Xunit;

namespace PasswordGeneratorLibrary.Tests
{
    public class PasswordGeneratorTests
    {
        [Fact]
        public void CanGenerateSalt()
        {
            using (var g = new PasswordGenerator())
            {
                var salt = g.GenerateSalt();
                salt.Content.Length.Should().BeGreaterOrEqualTo(4);
            }
        }

        [Fact]
        public void CanGeneratePassword()
        {
            using (var g = new PasswordGenerator())
            {
                var salt = g.GenerateSalt();

                var hash = g.GenerateHash("TESTPASSWORDMETWATEXTRATEXT", salt);
                hash.Should().NotBeNull();
                hash.Salt.Should().Be(salt);

                var hash2 = g.GenerateHash("TESTPASSWORDMETWATEXTRATEXT", salt);
                hash.Hash.Should().Be(hash2.Hash);
                hash.Salt.Should().Be(hash2.Salt);
            }
        }
    }
}
