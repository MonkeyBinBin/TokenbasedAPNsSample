using HttpTwo;
using Jose;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;

namespace TokenbasedAPNsSample
{
    class Program
    {
        static void Main(string[] args)
        {
            TokenBasedAuthenticationAPNsPush("測試推播訊息，使用APNs Auth Key.", 2, "ping.aiff");
            Console.ReadLine();
        }

        /// <summary>
        /// Token Based Authentication APNs 推播
        /// </summary>
        /// <param name="message">推播訊息</param>
        /// <param name="badge">badge數量</param>
        /// <param name="sound">推播聲音檔名</param>
        static async void TokenBasedAuthenticationAPNsPush(string message, int badge, string sound)
        {
            string algorithm = "ES256";

            string apnsKeyId = "<APNs Auth Key ID>";
            string teamId = "<Team ID get from Apple Developer Membership Details>";           
            string authKeyPath = "<APNs Auth Key download from Apple Developer>";

            string bundleId = "<Identifiers App ID>";
            string registrationId = "<Device Token>";

            //讀取下載的加密私鑰(.p8)
            var privateKeyContent = System.IO.File.ReadAllText(authKeyPath);
            var privateKey = privateKeyContent.Split('\n')[1];

            var secretKeyFile = Convert.FromBase64String(privateKey);
            var secretKey = CngKey.Import(secretKeyFile, CngKeyBlobFormat.Pkcs8PrivateBlob);

            var expiration = DateTime.Now.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var expirationSeconds = (long)expiration.TotalSeconds;

            var payload = new Dictionary<string, object>()
            {
                { "iss", teamId },
                { "iat", expirationSeconds }
            };
            var header = new Dictionary<string, object>()
            {
                { "alg", algorithm },
                { "kid", apnsKeyId }
            };

            string accessToken = Jose.JWT.Encode(payload, secretKey, JwsAlgorithm.ES256, header);

            //Development server:api.development.push.apple.com:443
            //Production server:api.push.apple.com:443
            string host = "api.development.push.apple.com";
            int port = 443;

            // Uri to request
            var uri = new Uri(string.Format("https://{0}:{1}/3/device/{2}", host, port, registrationId));

            var payloadData = JObject.FromObject(new
            {
                aps = new
                {
                    alert = message,
                    badge = badge,
                    sound = sound
                }
            });

            //UTF8編碼避免中文無法正常顯示
            byte[] data = System.Text.Encoding.UTF8.GetBytes(payloadData.ToString());

            var handler = new Http2MessageHandler();
            var httpClient = new HttpClient(handler);
            var requestMessage = new HttpRequestMessage();
            requestMessage.RequestUri = uri;
            requestMessage.Headers.Add("authorization", string.Format("bearer {0}", accessToken));
            requestMessage.Headers.Add("apns-id", Guid.NewGuid().ToString());
            requestMessage.Headers.Add("apns-expiration", "0");
            requestMessage.Headers.Add("apns-priority", "10");
            requestMessage.Headers.Add("apns-topic", bundleId);
            requestMessage.Method = HttpMethod.Post;
            requestMessage.Content = new ByteArrayContent(data);

            try
            {
                var responseMessage = await httpClient.SendAsync(requestMessage);
                if (responseMessage.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    string responseUuid = string.Empty;
                    IEnumerable<string> values;
                    if (responseMessage.Headers.TryGetValues("apns-id", out values))
                    {
                        responseUuid = values.First();
                    }
                    Console.WriteLine(string.Format("\n\r*******Send Success [{0}]", responseUuid));
                }
                else
                {
                    var body = await responseMessage.Content.ReadAsStringAsync();
                    var json = new JObject();
                    json = JObject.Parse(body);

                    var reasonStr = json.Value<string>("reason");
                    Console.WriteLine("\n\r*******Failure reason => " + reasonStr);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n\r*******Exception message => " + ex.Message);
            }
        }
    }
}
