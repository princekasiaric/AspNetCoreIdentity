using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;

        public IdentityController(UserManager<IdentityUser> userManager, 
                                  SignInManager<IdentityUser> signInManager,
                                  RoleManager<IdentityRole> roleManager,
                                  IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
        }

        public IActionResult Signup()
        {
            var model = new SignupViewModel() { Role = "Member"};
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (!(await _roleManager.RoleExistsAsync(model.Role)))
                {
                    var role = new IdentityRole { Name = model.Role };
                    var result = await _roleManager.CreateAsync(role);
                    if (!result.Succeeded)
                    {
                        var errors = result.Errors.Select(s => s.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                        return View(model);
                    }
                }

                if (await _userManager.FindByEmailAsync(model.Email) == null)
                {
                    var user = new IdentityUser
                    {
                        UserName = model.Email,
                        Email = model.Email
                    };
                    var result = await _userManager.CreateAsync(user, model.Password);
                    //user = await _userManager.FindByEmailAsync(model.Email);
                    //var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    if (result.Succeeded)
                    {
                        //var confirmationLink = Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, token });
                        //await _emailSender.SendEmailAsync("info@mydomain.com", model.Email, "Confirm Your Email Address...", confirmationLink);
                        
                        //var claim = new Claim("Department", model.Department);
                        //await _userManager.AddClaimAsync(user, claim);

                        await _userManager.AddToRoleAsync(user, model.Role);
                        return RedirectToAction(nameof(Signin));
                    }
                    ModelState.AddModelError("Signup", string.Join("", result.Errors.Select(e => e.Description)));
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, returnUrl);
            var callBackUrl = Url.Action("ExternalLoginCallBack");
            properties.RedirectUri = callBackUrl;
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallBack()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            var emailClaim = info.Principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
            var user = new IdentityUser
            {
                Email = emailClaim.Value,
                UserName = emailClaim.Value
            };
            //var userId = await _userManager.GetUserIdAsync(user);
            if (await _userManager.GetUserIdAsync(user) == null)
            {
                await _userManager.CreateAsync(user);
                await _userManager.AddLoginAsync(user, info);
            }
            await _signInManager.SignInAsync(user, false);

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public async Task<IActionResult> MFASetup()
        {
            const string provider = "AspIdentity";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var qrCodeUrl = $"otpauth://totp/{provider}:{user.Email}?secret={token}&issuer={provider}&digits=6";

            var model = new MFASetupViewModel { Token = token, QRCodeUrl = qrCodeUrl };
            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFASetupViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Code could not be verified.");
                }
            }
            return View(model);
        }

        public IActionResult MFACheck()
        {
            return View(new MFACheckViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> MFACheck(MFACheckViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, false, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home", null);
                }
            }
            return View();
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return RedirectToAction("Signin");
            }
            return new NotFoundResult();
        }

        public IActionResult Signin()
        {
            return View(new SigninViewModel());
        }
        [HttpPost]
        public async Task<IActionResult> Signin(SigninViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                {
                    if (result.RequiresTwoFactor)
                    {
                        var user = await _userManager.FindByEmailAsync(model.Username);
                        var userClaims = await _userManager.GetClaimsAsync(user);
                        if (await _userManager.IsInRoleAsync(user, "Member"))
                        {
                            return RedirectToAction("Member", "Home");
                        }
                        return RedirectToAction(nameof(MFACheck));
                    }
                    else
                    {
                        if (!result.Succeeded)
                        {
                            ModelState.AddModelError("Login", "Cannot Login.");
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                }
                //if (result.Succeeded)
                //{
                //    var user = await _userManager.FindByEmailAsync(model.Username);

                //    var userClaims = await _userManager.GetClaimsAsync(user);
                //    if (!userClaims.Any(x => x.Type == "Department"))
                //    {
                //        ModelState.AddModelError("Claim", "User not in tech department.");
                //        return View(model);
                //    }

                //    if (await _userManager.IsInRoleAsync(user, "Member"))
                //    {
                //        return RedirectToAction("Member", "Home");
                //    }
                //    return RedirectToAction("AccessDenied");
                //}
                // ModelState.AddModelError("Login", "Login failed.");
            }
            return View(model);
        }

        public async Task<IActionResult> Signout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}