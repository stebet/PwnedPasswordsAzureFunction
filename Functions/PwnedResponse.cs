using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace Functions
{
    /// <summary>
    /// Helper class which creates the response for a pwned passwords API request
    /// </summary>
    public static class PwnedResponse
    {
        private static MediaTypeHeaderValue PlainTextHeaderValue = new MediaTypeHeaderValue("text/plain");
        private static UTF8Encoding UTF8WithoutBomEncoding = new UTF8Encoding(false);
        private static CacheControlHeaderValue CacheControlHeaderValue = new CacheControlHeaderValue { MaxAge = TimeSpan.FromDays(31), Public = true };

        /// <summary>
        /// Creates a response from the 
        /// </summary>
        /// <param name="req">Client HTTP request message</param>
        /// <param name="code">Status code to return to the client</param>
        /// <param name="content">The content to pass to the client. Either use this to return a status message or stream</param>
        /// <param name="stream">Stream from a file to pass as a response. This is primarily used for serving hash prefix files to clients.</param>
        /// <param name="lastModified">Last Modified date time to set for the response headers</param>
        /// <returns>Constructed HttpResponseMessage to serve to the client</returns>
        public static HttpResponseMessage CreateResponse(HttpRequestMessage req, HttpStatusCode code, string content = null, Stream stream = null, DateTimeOffset? lastModified = null)
        {
            var msg = new HttpResponseMessage(code);

            if (stream != null)
            {
                msg.Content = new StreamContent(stream);
                
                msg.Content.Headers.ContentType = PlainTextHeaderValue;

                if (lastModified != null)
                {
                    msg.Content.Headers.LastModified = lastModified;
                }
            }
            else
            {
                msg.Content = content == null ? null : new StringContent(content, UTF8WithoutBomEncoding, "text/plain");
            }

            msg.Headers.CacheControl = CacheControlHeaderValue;
            msg.Headers.Add("Arr-Disable-Session-Affinity", "True");
            msg.Headers.Add("Access-Control-Allow-Origin", "*");

            return msg;
        }
    }
}
