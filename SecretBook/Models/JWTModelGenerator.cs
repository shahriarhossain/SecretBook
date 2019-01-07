using AuthenticationService.Interface;
using System.Security.Claims;

namespace CRUD_API_JWT.Models
{
    public static class JWTModelGenerator
    {
        public static JWTContainerModel GetJWTContainerModel(string name, string email, string instrumentalKey)
        {
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.NameIdentifier, instrumentalKey)
                }
            };
        }
    }
}