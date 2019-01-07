using System.Security.Claims;
using CRUD_API_JWT.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Interface
{
    public class JWTContainerModel : IAuthContainerModel
    {
        public int ExpireMinutes { get; set; } = ApplicationConstants.JWTExpireTime; 
        public string SecretKey { get; set; } = ApplicationConstants.JWTSecretKey; // This secret key should be moved to some configurations outter server.
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        public Claim[] Claims { get; set; }
    }
}
