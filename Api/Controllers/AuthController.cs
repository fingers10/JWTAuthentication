using Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static readonly Dictionary<string, string> _userTokens = new Dictionary<string, string> { { "abdul", null } };

        [Route("login")]
        [HttpPost]
        public IActionResult Login([FromBody]LoginModel user)
        {
            if (user == null)
            {
                return BadRequest("Invalid client request");
            }

            if (user.UserName == "abdul" && user.Password == "demo@123")
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, "Admin")
                };

                JwtSecurityToken tokeOptions = GenerateToken(claims);

                var refreshToken = GenerateRefreshToken();
                SaveRefreshToken(user.UserName, refreshToken);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
                return Ok(new { Token = tokenString, RefreshToken = refreshToken });
            }
            else
            {
                return Unauthorized();
            }
        }

        [Route("refresh")]
        [HttpPost]
        public IActionResult Refresh(RefreshTokenModel token)
        {
            var principal = GetPrincipalFromExpiredToken(token.Token);
            var username = principal.Identity.Name;
            var savedRefreshToken = GetRefreshToken(username); //retrieve the refresh token from a data store
            if (savedRefreshToken != token.RefreshToken)
                throw new SecurityTokenException("Invalid refresh token");

            var newJwtToken = GenerateToken(principal.Claims);
            var newRefreshToken = GenerateRefreshToken();
            DeleteRefreshToken(username);
            SaveRefreshToken(username, newRefreshToken);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(newJwtToken);
            return Ok(new { Token = tokenString, RefreshToken = newRefreshToken });
        }

        private JwtSecurityToken GenerateToken(IEnumerable<Claim> claims)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345"));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokeOptions = new JwtSecurityToken(
                issuer: "http://localhost:44348",
                audience: "http://localhost:44348",
                claims: claims,
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: signinCredentials
            );
            return tokeOptions;
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345")),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private string GetRefreshToken(string username)
        {
            return _userTokens[username];
        }

        private void DeleteRefreshToken(string username)
        {
            _userTokens[username] = null;
        }

        private void SaveRefreshToken(string username, string newRefreshToken)
        {
            _userTokens[username] = newRefreshToken;
        }
    }
}