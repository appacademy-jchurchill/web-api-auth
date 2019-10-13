using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using WebApiAuth.MessageHandlers;

namespace WebApiAuth
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Add custom message handlers
            config.MessageHandlers.Add(new BasicAuthHandler());

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
