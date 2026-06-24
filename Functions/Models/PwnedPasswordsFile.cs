namespace HaveIBeenPwned.PwnedPasswords.Models;

public readonly struct PwnedPasswordsFile(Stream content, DateTimeOffset lastModified, string etag, byte[] contentHash = null)
{
    public Stream Content { get; } = content;
    public DateTimeOffset LastModified { get; } = lastModified;
    public string ETag { get; } = etag;
    public byte[] ContentHash { get; } = contentHash;
}
