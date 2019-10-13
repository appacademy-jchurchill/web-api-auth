using System;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WebApiAuth.MessageHandlers
{
    public class BasicAuthHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!ValidateAuthorizationHeader(request))
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue("basic"));
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }

            return base.SendAsync(request, cancellationToken);
        }

        private bool ValidateAuthorizationHeader(HttpRequestMessage message)
        {
            var authorizationHeader = message.Headers.Authorization;

            // Check that...
            // 1) We have an authorization header value
            // 2) The authorization scheme is "basic"
            // 3) And we have an authorization parameter value.
            if (authorizationHeader != null && 
                authorizationHeader.Scheme != null && 
                authorizationHeader.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && 
                authorizationHeader.Parameter != null)
            {
                string username = null;
                if (AuthenticateUser(authorizationHeader.Parameter, out username))
                {
                    var identity = new GenericIdentity(username);
                    var principal = new GenericPrincipal(identity, null);

                    var context = message.GetRequestContext();
                    context.Principal = principal;

                    return true;
                }
            }

            return false;
        }

        private bool AuthenticateUser(string base64EncodedCredentials, out string returnUsername)
        {
            returnUsername = null;

            try
            {
                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string credentials = encoding.GetString(Convert.FromBase64String(base64EncodedCredentials));

                int separator = credentials.IndexOf(':');
                string username = credentials.Substring(0, separator);
                string password = credentials.Substring(separator + 1);

                if (CheckUsernameAndPassword(username, password))
                {
                    returnUsername = username;
                    return true;
                }
            }
            catch (FormatException) { }

            return false;
        }

        private static bool CheckUsernameAndPassword(string username, string password)
        {
            return username == "user" && password == "password";
        }
    }
}