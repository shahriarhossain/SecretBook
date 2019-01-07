using AuthenticationService.Interface;
using AuthenticationService.Managers;
using CRUD_API_JWT.Filters;
using CRUD_API_JWT.Helper;
using CRUD_API_JWT.Models;
using System.Web.Http;
using System.Web.Http.Cors;

namespace SecretBook.Controllers
{
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class ValuesController : ApiController
    {
        [HttpGet]
        public string TokenGenerator(string email, string instrumentalKey)
        {
            IAuthContainerModel model = JWTModelGenerator.GetJWTContainerModel("Admin", email, instrumentalKey);
            IAuthService authService = new JWTService(model.SecretKey);

            string token = authService.GenerateToken(model);
            return token;
        }

        [JWTAuthenticationFilter]
        public string Get()
        {
            return "Returning secure data....";
        }

        [HttpGet]
        [JWTAuthenticationFilter]
        public FTPInfo GetFTPInfo()
        {
            return new FTPInfo()
            {
                Host = "www.test.com/",
                Password = Cryptography.Encrypt("veryStrongPassword"),
                Port = "20",
                UserName = Cryptography.Encrypt("putin")
            };
        }
    }
}
