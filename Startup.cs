using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityNetCore.Data;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace IdentityNetCore
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionSring = Configuration["ConnectionStrings:Default"];
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionSring));
            services.AddIdentity<IdentityUser, IdentityRole>()
                    .AddEntityFrameworkStores<ApplicationDbContext>()
                    .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(option =>
            {
                option.Password.RequiredLength = 3;
                option.Password.RequireDigit = true;
                option.Password.RequireNonAlphanumeric = false;
                option.Password.RequireUppercase = false;

                option.Lockout.AllowedForNewUsers = true;
                option.Lockout.MaxFailedAccessAttempts = 3;
                option.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

                option.User.RequireUniqueEmail = true;

                option.SignIn.RequireConfirmedEmail = false;
            });

            services.ConfigureApplicationCookie(option =>
            {
                option.LoginPath = "/Identity/Signin";
                option.AccessDeniedPath = "/Identity/AccessDenied";
                option.ExpireTimeSpan = TimeSpan.FromHours(10);
            });

            services.AddAuthentication().AddFacebook(option =>
            {
                option.AppId = Configuration["FacebookAppId"];
                option.AppSecret = Configuration["FacebookAppSecret"];
            });
            services.Configure<SmtpOptions>(Configuration.GetSection("Smtp"));

            services.AddSingleton<IEmailSender, SmtpEmailSender>();
            services.AddAuthorization(option =>
            {
                option.AddPolicy("MemberDep", policy =>
                {
                    policy.RequireClaim("Department", "Technical").RequireRole("Member");
                });
                option.AddPolicy("AdminDep", policy =>
                {
                    policy.RequireClaim("Department", "Technical").RequireRole("Admin");
                });
            });

            services.AddControllersWithViews();

            var issuerString = Configuration["Tokens:Issuer"];
            var audienceString = Configuration["Tokens:Audience"];
            var keyString = Configuration["Tokens:Key"];

            services.AddAuthentication().AddJwtBearer(option =>
            {
                option.SaveToken = true;
                option.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = issuerString,
                    ValidAudience = audienceString,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString))
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
