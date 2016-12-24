using FluentAssertions;
using System;
using System.Linq;
using Xunit;

namespace PasswordGeneratorLibrary.Tests
{
    public class PasswordGeneratorTests
    {
        [Fact]
        public void CanHashPassword()
        {
            var g = new PasswordGenerator();
            var salt = g.GenerateSalt();
            salt.Length.Should().BeGreaterOrEqualTo(4);
        }

        [Fact]
        public void CanGeneratePassword()
        {
            var g = new PasswordGenerator();
            var salt = g.GenerateSalt(128);
            var hash = g.GenerateHash("TESTPASSWORDMETWATEXTRATEXT", salt);
            hash.Length.Should().BeGreaterOrEqualTo(4);

            var hash2 = g.GenerateHash("TESTPASSWORDMETWATEXTRATEXT", salt);
            hash.Should().Be(hash2);
        }
    }
}
