using System;
using System.IO;

namespace Functions
{
    /// <summary>
    /// Blob storage entry
    /// </summary>
    public class BlobStorageEntry
    {
        /// <summary>
        /// Initializes a new instance of <see cref="BlobStorageEntry"/>
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="lastModified"></param>
        public BlobStorageEntry(Stream stream, DateTimeOffset? lastModified)
        {
            Stream = stream;
            LastModified = lastModified;
        }

        /// <summary>
        /// Stream representing the blob contents
        /// </summary>
        public Stream Stream { get; }
        
        /// <summary>
        /// Pointer to the DateTimeOffset for the last time that the blob was modified
        /// </summary>
        public DateTimeOffset? LastModified { get; }
    }
}
