using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace WebApiAuth.Security
{
    public class BasicAuthenticationCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }



    public static class BasicAuthentication
    {
        public static BasicAuthenticationCredentials ExtractUsernameAndPassword(string authorizationParameter)
        {
            byte[] credentialBytes;

            try
            {
                credentialBytes = Convert.FromBase64String(authorizationParameter);
            }
            catch (FormatException)
            {
                return null;
            }

            // The currently approved HTTP 1.1 specification says characters here are ISO-8859-1.
            // However, the current draft updated specification for HTTP 1.1 indicates this encoding is infrequently
            // used in practice and defines behavior only for ASCII.
            Encoding encoding = Encoding.ASCII;
            // Make a writable copy of the encoding to enable setting a decoder fallback.
            encoding = (Encoding)encoding.Clone();
            // Fail on invalid bytes rather than silently replacing and continuing.
            encoding.DecoderFallback = DecoderFallback.ExceptionFallback;
            string decodedCredentials;

            try
            {
                decodedCredentials = encoding.GetString(credentialBytes);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

            if (string.IsNullOrEmpty(decodedCredentials))
            {
                return null;
            }

            int colonIndex = decodedCredentials.IndexOf(':');

            if (colonIndex == -1)
            {
                return null;
            }

            string username = decodedCredentials.Substring(0, colonIndex);
            string password = decodedCredentials.Substring(colonIndex + 1);

            return new BasicAuthenticationCredentials()
            {
                Username = username,
                Password = password
            };
        }

        public static Task<IPrincipal> AuthenticateAsync(string username, string password,
            CancellationToken cancellationToken)
        {
            // TODO Retrieve the user from the database using their username
            // and validate that the stored password matches the provided password.
            if (username != "user" || password != "password")
            {
                return Task.FromResult<IPrincipal>(null);
            }

            var identity = new GenericIdentity(username);
            var principal = new GenericPrincipal(identity, null);

            return Task.FromResult<IPrincipal>(principal);
        }
    }
}