using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class MFACheckViewModel
    {
        [Required]
        public string Code { get; set; }
    }
}
