using System.Text.Json;
using HaveIBeenPwned.PwnedPasswords;

if (args.Length != 2)
{
    throw new ArgumentException("This command requires two arguments.");
}

if (!File.Exists(args[0]))
{
    throw new ArgumentException($"File {args[0]} does not exist.");
}

if (File.Exists(args[1]))
{
    Console.WriteLine($"File {args[1]} already exists. It will be overwritten!");
}

var ntlmName = JsonEncodedText.Encode("ntlm");
var sha1Name = JsonEncodedText.Encode("sha1");
var numName = JsonEncodedText.Encode("num");

using FileStream input = File.OpenRead(args[0]);
using var inputReader = new StreamReader(input);
using FileStream output = File.Create(args[1]);
using var outputWriter = new StreamWriter(output);
int numPasswords = 0;
Dictionary<string, int> passwords = new();
while (!inputReader.EndOfStream)
{
    string? line = await inputReader.ReadLineAsync().ConfigureAwait(false);
    if (line != null)
    {
        passwords[line] = passwords.TryGetValue(line, out int prevalence) ? prevalence + 1 : 1;
        /*
        if (line.LastIndexOf(":") <= 0 || !int.TryParse(line.AsSpan()[line.LastIndexOf(":")..], out int prevalence))
        {
            prevalence = Random.Shared.Next(100) + 1;
        }
        */
    }
}

foreach (KeyValuePair<string, int> password in passwords)
{
    outputWriter.WriteLine($"{HashExtensions.CreateSHA1Hash(password.Key)}:{HashExtensions.CreateNTLMHash(password.Key)}:{password.Value}");
    numPasswords++;
}

await outputWriter.FlushAsync().ConfigureAwait(false);
Console.WriteLine($"Finished preparing {numPasswords} passwords into {args[1]}.");
