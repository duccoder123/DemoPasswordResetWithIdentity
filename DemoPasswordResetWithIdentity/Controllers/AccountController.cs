using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoPasswordResetWithIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {

        private async Task<IdentityUser>? GetUser(string email) => await userManager.FindByEmailAsync(email);

        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            var result = await userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,   
                Email = email,
                PasswordHash = password
            }, password);

            return Ok(result);
        }

        private string GenerateToken(IdentityUser? user)
        {
            var creditials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Abcxyz123456789QWERTyuiopzxczxcxzc")), SecurityAlgorithms.HmacSha256);

            var claims = new[]{
               new Claim(JwtRegisteredClaimNames.Email, user.Email!)
            };


            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: null,
                signingCredentials: creditials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            bool checkPassword = await userManager.CheckPasswordAsync(await GetUser(email), password);
            if (checkPassword)
                return Ok(new[] { "successfully logged in", GenerateToken(await GetUser(email)) });
            else
                return BadRequest();
        }

        [HttpPost("request-password-reset/{email}")]
        public async Task<IActionResult> RequestPasswordReset(string email)
        {
            var user = await GetUser(email);
            var resetToken = await userManager.GeneratePasswordResetTokenAsync(user!);
            string validToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes((string)resetToken));
            return Ok(SendEmail(user!.Email, validToken));
        }


        private string SendEmail(string? email, string validToken)
        {
            string resetLink = $"https://localhost:7074/account/reset-password/{validToken}";

            StringBuilder sb = new();

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"UTF8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.AppendLine("<title>Password Reset</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body {font-family: Arial, sans-serif; background-color: #f4f4f9; padding: 20px}");
            sb.AppendLine(" .email-container { max-width: 600px; margin : 0 auto; background-color:#fff; padding:20px; }");
            sb.AppendLine(" h1{color:#333;}");
            sb.AppendLine("p {color : #555}");
            sb.AppendLine(".button {background-color: #28a745; color : white; padding: 10px 20px; text-decoration:none");
            sb.AppendLine(".button:hover{background-color : #218838}");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div class=\"email-container\">");
            sb.AppendLine($"<h1>Hello, {email}</h1>");
            sb.AppendLine("<p>You requested to set a new passwrod for your account. Click the button below to set your password</p>");
            sb.AppendLine($"<p><a href=\"{resetLink}\" class=\"button\">Set your password</a></p>");
            sb.AppendLine("<p>If you didn't request this, please ignore this email</p>");
            sb.AppendLine("<p>Thank you,</p>");
            sb.AppendLine("</div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            string message = sb.ToString();
            var _email = new MimeMessage();
            _email.From.Add(MailboxAddress.Parse("michael.waters@ethereal.email"));
            _email.To.Add(MailboxAddress.Parse("michael.waters@ethereal.email"));
            _email.Subject = "Password Reset";
            _email.Body = new TextPart(TextFormat.Html) { Text = message };
            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("michael.waters@ethereal.email", "VtxW1D87qZRww8uqvU");
            smtp.Send(_email);
            smtp.Disconnect(true);
            return "Kindly check your email for password reset link";

        }

        public static string Token { get; set; } = string.Empty;
        [HttpGet("reset-password/{token}")]
        public IActionResult ResetPassword(string token)
        {
            Token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            return Ok("Reset password now!");
        }

        [HttpGet("reset-password/{email}/{newPassword}")]
        public async Task<IActionResult> ResetPassword(string email, string newPassword)
        {
            var result = await userManager.ResetPasswordAsync(await GetUser(email), Token, newPassword);
            return Ok(result);
        }
    }
}
