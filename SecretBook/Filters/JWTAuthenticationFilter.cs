using AuthenticationService.Managers;
using CRUD_API_JWT.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace CRUD_API_JWT.Filters
{
    public class JWTAuthenticationFilter : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext filterContext)
        {
            base.OnAuthorization(filterContext);
            try
            {
                var isUserAuthorized = IsUserAuthorized(filterContext);
                if (!isUserAuthorized.Item1)
                {
                    JWTService.ShowAuthenticationError(filterContext, isUserAuthorized.Item2);
                    return;
                } 
            }
            catch (Exception ex)
            {
                JWTService.ShowAuthenticationError(filterContext, ex.Message);
                return;
            }
        }

        public Tuple<bool, string>IsUserAuthorized(HttpActionContext actionContext)
         {
            var authHeader = FetchFromHeader(actionContext);
            JWTService jwtService = new JWTService(ApplicationConstants.JWTSecretKey);
            var isValidToken = jwtService.IsTokenValid(authHeader);

            if (authHeader != null && isValidToken.Item1)
            {
                IAuthService authService = new JWTService(ApplicationConstants.JWTSecretKey);

                List<Claim> claims = authService.GetTokenClaims(authHeader).ToList();
                //Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Name)).Value);
                //Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Email)).Value);
                //TODO: claim check....

                return new Tuple<bool, string>(true, null);
            }
            return new Tuple<bool, string>(false, isValidToken.Item2); ;
        }

        private string FetchFromHeader(HttpActionContext actionContext)
        {
            string requestToken = null;

            var authRequest = actionContext.Request.Headers.Authorization;
            if (authRequest != null)
            {
                requestToken = authRequest.Parameter;
            }
            return requestToken;
        }
    }
}