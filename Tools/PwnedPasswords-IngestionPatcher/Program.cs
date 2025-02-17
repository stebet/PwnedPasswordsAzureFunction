// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

using HaveIBeenPwned.PwnedPasswords;

Dictionary<string, List<HashEntry>> sha1Entries = [];
Dictionary<string, List<HashEntry>> ntlmEntries = [];

string inputfile = @"inputfile";
using FileStream inputFileStream = File.Open(inputfile, new FileStreamOptions()
{
    Access = FileAccess.Read,
    Mode = FileMode.Open,
    Options = FileOptions.SequentialScan
});
using var inputStreamReader = new StreamReader(inputFileStream);
int lineNum = 1;
byte[] sha1 = new byte[20];
byte[] ntlm = new byte[16];
byte[] sha1Buffer = new byte[4096];
byte[] ntlmBuffer = new byte[4096];
Range[] ranges = new Range[16];
string? line = inputStreamReader.ReadLine();
while (line != null)
{
    ReadOnlySpan<char> lineSpan = line.AsSpan();
    int splits = lineSpan.Split(ranges, ':');
    if (splits == 2 && int.TryParse(lineSpan[ranges[1]], out int prevalence) && lineSpan[ranges[0]].Length > 0)
    //if (items.Length == 3 && int.TryParse(items[2], out int prevalence) && items[0].Length == 40 && HashEntry.TryParseFromText(items[0], prevalence, out var sha1HashEntry) && items[1].Length == 32 && HashEntry.TryParseFromText(items[1], prevalence, out var ntlmHashEntry))
    {
        ReadOnlySpan<char> passwordLine = lineSpan[ranges[0]];
        int numSha1Bytes = Encoding.UTF8.GetBytes(passwordLine, sha1Buffer);
        int numNtlmBytes = Encoding.Unicode.GetBytes(passwordLine, ntlmBuffer);
        SHA1.HashData(sha1Buffer.AsSpan(0, numSha1Bytes), sha1);
        MD4.HashData(ntlmBuffer.AsSpan(0, numNtlmBytes), ntlm);
        HashEntry sha1HashEntry = new(sha1, prevalence);
        HashEntry ntlmHashEntry = new(ntlm, prevalence);
        string sha1Prefix = sha1HashEntry.HashText[..5];
        if (!sha1Entries.TryGetValue(sha1Prefix, out List<HashEntry>? sha1values))
        {
            sha1values = [];
            sha1Entries[sha1Prefix] = sha1values;
        }

        sha1values.Add(sha1HashEntry);

        string ntlmPrefix = ntlmHashEntry.HashText[..5];
        if (!ntlmEntries.TryGetValue(ntlmPrefix, out List<HashEntry>? ntlmvalues))
        {
            ntlmvalues = [];
            ntlmEntries[ntlmPrefix] = ntlmvalues;
        }

        ntlmvalues.Add(ntlmHashEntry);
        lineNum++;
    }
    else
    {
        Console.WriteLine($"Invalid line #{lineNum}: {line}");
    }

    if (lineNum % 100000 == 0)
    {
        Console.WriteLine($"Read {lineNum} hashes from {inputfile}");
    }

    line = inputStreamReader.ReadLine();
}

Console.WriteLine($"Done reading {lineNum} hashes from {inputfile}");

/*
foreach (string ingestionFile in Directory.EnumerateFiles($@"**REPLACE WITH INPUT**"))
{
    using (Stream stream = File.OpenRead(ingestionFile))
    {
        int count = 0;
        await foreach (PwnedPasswordsIngestionValue? entry in JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(stream))
        {
            if (entry != null)
            {
                entry.NTLMHash = entry.NTLMHash.ToUpperInvariant();
                string prefix = entry.NTLMHash[..5];
                if (!entries.TryGetValue(prefix, out List<HashEntry>? values))
                {
                    values = new List<HashEntry>();
                    entries[prefix] = values;
                }

                if (HashEntry.TryParseFromText(entry.NTLMHash, entry.Prevalence, out HashEntry hashEntry))
                {
                    values.Add(hashEntry);
                }

                count++;
            }
        }

        Console.WriteLine($"Read {count} entries from {ingestionFile}.");
    }
}

*/

int newSha1 = 0;
int newNtlm = 0;
int updatedSha1 = 0;
int updatedNtlm = 0;
int num = 0;
Console.WriteLine("Patching SHA1 files");
Parallel.ForEach(sha1Entries, WriteSHA1Entries);
num = 0;
Console.WriteLine("Patching NTLM files");
Parallel.ForEach(ntlmEntries, WriteNTLMEntries);

Console.WriteLine($"New SHA1 hashes: {newSha1}, updated: {updatedSha1}");
Console.WriteLine($"New NTLM hashes: {newNtlm}, updated: {updatedNtlm}");


void WriteSHA1Entries(KeyValuePair<string, List<HashEntry>> entry)
{
    (int NewHashes, int UpdatedHashes) = ParseAndUpdateHashFile(entry.Key, "C:\\source\\hibphashes\\sha1", "C:\\source\\hibphashes\\sha1patched", entry.Value, false);
    Interlocked.Add(ref newSha1, NewHashes);
    Interlocked.Add(ref updatedSha1, UpdatedHashes);
    sha1Entries.Remove(entry.Key);
    num++;
    if (num % 100000 == 0)
    {
        Console.WriteLine($"Done patching {num} SHA1 files.");
    }
}


void WriteNTLMEntries(KeyValuePair<string, List<HashEntry>> entry)
{
    (int NewHashes, int UpdatedHashes) = ParseAndUpdateHashFile(entry.Key, "C:\\source\\hibphashes\\ntlm", "C:\\source\\hibphashes\\ntlmpatched", entry.Value, false);
    Interlocked.Add(ref newNtlm, NewHashes);
    Interlocked.Add(ref updatedNtlm, UpdatedHashes);
    ntlmEntries.Remove(entry.Key);
    num++;
    if (num % 100000 == 0)
    {
        Console.WriteLine($"Done patching {num} NTLM files.");
    }
}

static (int NewHashes, int UpdatedHashes) ParseAndUpdateHashFile(string prefix, string sourcePath, string destPath, List<HashEntry> batchEntries, bool writeBinary)
{
    int numNew = 0;
    int numUpdated = 0;
    byte[] Newline = "\r\n"u8.ToArray();

    try
    {
        SortedSet<HashEntry> entries = [];

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        FileStream file = File.Open($@"{sourcePath}\{prefix.ToUpperInvariant()}.txt", new FileStreamOptions()
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Options = FileOptions.SequentialScan
        });
        using StreamReader reader = new(file);
        string? line = reader.ReadLine();
        while (line != null)
        {
            if (HashEntry.TryParseFromText(line, out HashEntry entry))
            {
                entries.Add(entry);
            }

            line = reader.ReadLine();
        }

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffixes with the prevalence counts.
        foreach (HashEntry item in batchEntries)
        {
            if (entries.TryGetValue(item, out HashEntry value))
            {
                value.Prevalence += item.Prevalence;
                numUpdated++;
            }
            else
            {
                entries.Add(item);
                numNew++;
            }
        }

        file.Dispose();

        file = File.Open($@"{destPath}\{prefix.ToUpperInvariant()}.{(writeBinary ? "bin" : "txt")}", new FileStreamOptions()
        {
            Access = FileAccess.Write,
            Mode = FileMode.Create
        });

        if (writeBinary)
        {
            var pipeWriter = PipeWriter.Create(file);
            foreach (HashEntry item in entries)
            {
                item.WriteAsBinaryTo(pipeWriter, true);
            }

            pipeWriter.Complete();
            pipeWriter.FlushAsync().AsTask().Wait();
        }
        else
        {
            using StreamWriter writer = new(file);
            foreach (HashEntry item in entries)
            {
                writer.WriteLine(item.ToString());
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.ToString());
    }

    return (numNew, numUpdated);
}
