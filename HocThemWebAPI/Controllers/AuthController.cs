using HocThemWebAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HocThemWebAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            //if ((username != "a") || (password != "a"))
            //    return BadRequest(new { message = "Username or password is incorrect" });
            Users loginUser = CreateDummyUsers().Where(a => a.Username == username && a.Password == password).FirstOrDefault();
            if (loginUser == null)
                return new JsonResult("Login Failed");

            var claims = new[] {
                new Claim(ClaimTypes.Role, loginUser.Role)
            };
            var accessToken = GenerateJSONWebToken(claims);
            SetJWTCookie(accessToken);

            return new JsonResult(accessToken);
        }

        private string GenerateJSONWebToken(Claim[] claims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MynameisCodelaGhien"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "https://hoc.codelaghien.club",
                audience: "https://hoc.codelaghien.club",
                expires: DateTime.Now.AddHours(3),
                signingCredentials: credentials,
                claims: claims
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private void SetJWTCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddHours(3),
            };
            Response.Cookies.Append("jwtCookie", token, cookieOptions);
        }

        private List<Users> CreateDummyUsers()
        {
            List<Users> userList = new List<Users> {
                new Users { Username = "a", Password = "a", Role = "Admin" },
                new Users { Username = "b", Password = "b", Role = "Manager" },
                new Users { Username = "c", Password = "c", Role = "Developer" }
            };
            return userList;
        }
    }
}
