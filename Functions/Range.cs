using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public static class Range
    {
        public static BlobStorage _blobStorage = null;

        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns></returns>
        [FunctionName("Range-GET")]
        public static Task<HttpResponseMessage> RunRoute([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestMessage req, string hashPrefix, TraceWriter log)
        {
            return GetData(req, hashPrefix, log);
        }

        /// <summary>
        /// Get the data for the request
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Http Response message to return to the client</returns>
        private static async Task<HttpResponseMessage> GetData(HttpRequestMessage req, string hashPrefix, TraceWriter log)
        {
            if (string.IsNullOrEmpty(hashPrefix))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing hash prefix");
            }

            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The hash prefix was not in a valid format");
            }

            // Let's initialize the blob storage if needed.
            _blobStorage = _blobStorage ?? new BlobStorage(log);
            (Stream stream, DateTimeOffset? lastModified) = await _blobStorage.GetByHashesByPrefix(hashPrefix.ToUpperInvariant());
            var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, stream, lastModified);
            return response;
        }
    }
}
