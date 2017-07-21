
namespace PasswordGeneratorLibrary
{
    public class HashedPassword
    {
        public Salt Salt { get; set; }
        public string Hash { get; set; }
    }
}
