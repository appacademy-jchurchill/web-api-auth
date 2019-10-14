using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;
using WebApiAuth.Results;
using WebApiAuth.Security;

namespace WebApiAuth.Filters
{
    public class BasicAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public string Realm { get; set; }

        public virtual bool AllowMultiple
        {
            get { return false; }
        }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            HttpRequestMessage request = context.Request;
            AuthenticationHeaderValue authorization = request.Headers.Authorization;

            if (authorization == null || authorization.Scheme != "Basic")
            {
                // No authentication was attempted (for this authentication method).
                // Do not set either Principal (which would indicate success) or ErrorResult (indicating an error).
                return;
            }

            if (string.IsNullOrEmpty(authorization.Parameter))
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new AuthenticationFailureResult("Missing credentials", request);
                return;
            }

            var credentials = BasicAuthentication.ExtractUsernameAndPassword(authorization.Parameter);

            if (credentials == null)
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new AuthenticationFailureResult("Invalid credentials", request);
                return;
            }

            IPrincipal principal = await AuthenticateAsync(
                credentials.Username, credentials.Password, cancellationToken);

            if (principal == null)
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new AuthenticationFailureResult("Invalid username or password", request);
            }
            else
            {
                // Authentication was attempted and succeeded. Set Principal to the authenticated user.
                context.Principal = principal;
            }
        }

        protected Task<IPrincipal> AuthenticateAsync(string username, string password,
            CancellationToken cancellationToken)
        {
            if (username != "user" || password != "password")
            {
                return Task.FromResult<IPrincipal>(null);
            }

            var identity = new GenericIdentity(username);
            var principal = new GenericPrincipal(identity, null);

            return Task.FromResult<IPrincipal>(principal);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
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

            context.Result = new AddChallengeOnUnauthorizedResult(
                new AuthenticationHeaderValue("Basic", parameter), context.Result);

            return Task.FromResult(0);
        }
    }
}