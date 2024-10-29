using api.Models;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly IConfiguration? _configuration;

        public  LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] User user)
        {
            using (var connection = new SqlConnection(_configuration?.GetConnectionString("DefaultConnection")))
            {
                var sql = "SELECT [ID], [Username], [Password], [Salt], [IsAdmin] FROM [Users] WHERE [Username] = @Username";
                var dbUser = await connection.QueryFirstOrDefaultAsync<User>(sql, new { user.Username });

                if (dbUser != null && !string.IsNullOrEmpty(dbUser.Username))
                {
                    var hashedPassword = PasswordHasher.HashPassword(user.Password, dbUser.Salt!);
                    if (hashedPassword == dbUser.Password)
                    {
                        var token = GenerateJwtToken(dbUser.Username, dbUser.isAdmin!.Value);
                        return Ok(new { token = token });   
                    }
                }
                return Unauthorized();
            }
        }

        private string GenerateJwtToken(string username, bool isAdmin)
        {
            var key = _configuration?["Jwt:Key"] ?? throw new InvalidOperationException("JWT key is missing");
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, isAdmin ? "Admin" : "User")
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:DurationInMinutes"])),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
