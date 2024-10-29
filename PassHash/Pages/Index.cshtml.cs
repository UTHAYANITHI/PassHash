using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using PassCodeManager.Payloads;
using PassCodeManager.Views;
using System.Security.Cryptography;

namespace PassCodeManager.Pages
{
    public class EncodeModel : PageModel
    {
        private readonly ILogger<EncodeModel> _logger;

        public EncodeModel(ILogger<EncodeModel> logger)
        {
            _logger = logger;
        }

        [BindProperty(SupportsGet = true)]
        public EncodePayload EncodePayload { set; get; }

        [BindProperty(SupportsGet = true)]
        public HashedPassword EncodeView { set; get; }

        public IActionResult OnGet()
        {
            return Page();
        }

        public IActionResult Onpost()
        {
            if (EncodePayload.Password != null)
            {
                byte[] _salt = new byte[128 / 8];

                using (var r = RandomNumberGenerator.Create())
                {
                    r.GetBytes(_salt);
                }

                string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    password: EncodePayload.Password,
                    salt: _salt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: 10000,
                    numBytesRequested: 256 / 8
                ));

                EncodeView.Salt = Convert.ToBase64String(_salt);
                EncodeView.Password = hashed;
            }

            return Page();
        }
    }
}