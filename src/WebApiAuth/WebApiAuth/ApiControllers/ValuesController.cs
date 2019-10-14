using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using WebApiAuth.Filters;

namespace WebApiAuth.ApiControllers
{
    [BasicAuthentication]
    [Authorize]
    public class ValuesController : ApiController
    {
        public IEnumerable<string> Get()
        {
            return new string[]
            {
                "Red",
                "Green",
                "Blue"
            };
        }
    }
}