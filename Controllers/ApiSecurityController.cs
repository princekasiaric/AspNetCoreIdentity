using IdentityNetCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiSecurityController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public ApiSecurityController(IConfiguration config, 
                                     SignInManager<IdentityUser> signInManager, 
                                     UserManager<IdentityUser> userManager)
        {
            _config = config;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [Route(template:"Auth")]
        [HttpPost]
        public async Task<IActionResult> TokenAuth(SigninViewModel model)
        {
            // To get tokens from appsettings.json
            var issuerString = _config["Tokens:Issuer"];
            var audienceString = _config["Tokens:Audience"];
            var keyString = _config["Tokens:Key"];

            if (ModelState.IsValid)
            {
                var signInResult = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);
                if (signInResult.Succeeded)
                {
                    // Fetch user from the db
                    var user = await _userManager.FindByEmailAsync(model.Username);
                    if (user != null)
                    {
                        // Claims to return to the signed in user
                        var claims = new[]
                        {
                            new Claim(type:JwtRegisteredClaimNames.Email, value:user.Email),
                            new Claim(type:JwtRegisteredClaimNames.Jti, value:user.Id)
                        };

                        // Convert the key string to bytes array
                        var keyBytes = Encoding.UTF8.GetBytes(keyString);
                        // Create the symmetric key
                        var theKey = new SymmetricSecurityKey(keyBytes);
                        // Create credential on the key created
                        var cred = new SigningCredentials(theKey, SecurityAlgorithms.HmacSha256);
                        // Craete the token
                        var token = new JwtSecurityToken(issuerString, audienceString, claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: cred);

                        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                    }
                }
            }
            return BadRequest();
        }
    }
}