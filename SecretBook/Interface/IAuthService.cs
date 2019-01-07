using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Interface;
using System;

namespace AuthenticationService.Managers
{
    public interface IAuthService
    {
        string SecretKey { get; set; }
        Tuple<bool, string> IsTokenValid(string token);
        string GenerateToken(IAuthContainerModel model);
        IEnumerable<Claim> GetTokenClaims(string token);
    }
}
