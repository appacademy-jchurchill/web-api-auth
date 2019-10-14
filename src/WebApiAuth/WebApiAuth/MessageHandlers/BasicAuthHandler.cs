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
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool result = await ValidateAuthorizationHeader(request, cancellationToken);

            if (!result)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue("basic"));
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