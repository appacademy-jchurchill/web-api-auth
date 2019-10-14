using System;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using WebApiAuth.Security;

namespace WebApiAuth.MessageHandlers
{
    public class BasicAuthHandler : DelegatingHandler
    {
        private const string Realm = "";

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool result = await ValidateAuthorizationHeader(request, cancellationToken);

            if (!result)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);

                string parameter;

                if (string.IsNullOrEmpty(Realm))
                {
                    parameter = null;
                }
                else
                {
                    // A correct implementation should verify that Realm does not contain a quote character unless properly
                    // escaped (precededed by a backslash that is not itself escaped).
                    parameter = "realm=\"" + Realm + "\"";
                }

                response.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", parameter));

                return response;
            }

            return await base.SendAsync(request, cancellationToken);
        }

        private async Task<bool> ValidateAuthorizationHeader(HttpRequestMessage message, CancellationToken cancellationToken)
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
                var credentials = BasicAuthentication.ExtractUsernameAndPassword(authorizationHeader.Parameter);

                if (credentials != null)
                {
                    IPrincipal principal = await BasicAuthentication.AuthenticateAsync(
                        credentials.Username, credentials.Password, cancellationToken);

                    if (principal != null)
                    {
                        var context = message.GetRequestContext();
                        context.Principal = principal;

                        return true;
                    }
                }
            }

            return false;
        }
    }
}