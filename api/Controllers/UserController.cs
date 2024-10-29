using api.Models;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class UserController : ControllerBase
    {

        private readonly IConfiguration? _configuration;

        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            using (var connection = new SqlConnection(_configuration?.GetConnectionString("DefaultConnection")))
            {
                var sql = "SELECT u.[Username], c.[Name] AS [Company], u.[IsAdmin] FROM [Users] u INNER JOIN [Company] c ON c.[ID] = u.[Company] " + (User.IsInRole("User") ? " WHERE [IsAdmin] = 0" : "");
                var user = await connection.QueryAsync(sql);

                if (user == null)
                    return NotFound();

                return Ok(user);
            }
        }

        [HttpPost]
        [Authorize(Roles = "Admin")] 
        public async Task<IActionResult> Create(User user)
        {
            using (var connection = new SqlConnection(_configuration?.GetConnectionString("DefaultConnection")))
            {
                var sql = "INSERT INTO [Users] ([Username], [Password], [IsAdmin]) VALUES (@Username, @Password, @IsAdmin)";
                var result = await connection.ExecuteAsync(sql, user);
                return result > 0 ? Ok(user) : BadRequest();
            }
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Update(int id, User user)
        {
            using (var connection = new SqlConnection(_configuration?.GetConnectionString("DefaultConnection")))
            {
                var sql = "UPDATE [Users] SET [Username] = @Username, [Password] = @Password, [IsAdmin] = @IsAdmin WHERE [Id] = @Id";
                var result = await connection.ExecuteAsync(sql, new { Id = id, user.Username, user.Password, user.isAdmin});

                return result > 0 ? Ok(user) : BadRequest();
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int id)
        {
            using (var connection = new SqlConnection(_configuration?.GetConnectionString("DefaultConnection")))
            {
                var sql = "DELETE FROM [Users] WHERE [Id] = @Id";
                var result = await connection.ExecuteAsync(sql, new { Id = id });

                return result > 0 ? Ok() : NotFound();
            }
        }
    }
}
