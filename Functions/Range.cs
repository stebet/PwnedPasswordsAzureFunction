using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly BlobStorage _blobStorage;
        private static readonly IActionResult NotFound = new ContentResult() { StatusCode = StatusCodes.Status404NotFound, Content = "The hash prefix was not found", ContentType = "text/plain" };
        private static readonly IActionResult InvalidFormat = new ContentResult() { StatusCode = StatusCodes.Status400BadRequest, Content = "The hash prefix was not in a valid format", ContentType = "text/plain" };
        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        public Range(BlobStorage blobStorage)
        {
            _blobStorage = blobStorage;
        }
        
        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [FunctionName("Range-GET")]
        public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequest req, string hashPrefix)
        {
            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return InvalidFormat;
            }

            BlobStorageEntry? entry = await _blobStorage.GetByHashesByPrefix(hashPrefix.ToUpper());
            return entry == null ? NotFound : new FileStreamResult(entry.Stream, "text/plain") { LastModified = entry.LastModified };
        }
    }
}
