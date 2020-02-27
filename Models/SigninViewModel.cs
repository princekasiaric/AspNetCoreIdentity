using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class SigninViewModel
    {
        [Required(ErrorMessage ="Username is required.")] // Display(Name ="Username")
        [DataType(DataType.EmailAddress)]
        public string Username { get; set; }
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
