using System.ComponentModel.DataAnnotations;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AceJobAgency.Pages.Membership;

[AllowAnonymous]
public class RegisterModel : PageModel
{
    private const long MaxResumeFileSizeBytes = 5 * 1024 * 1024;
    private static readonly HashSet<string> AllowedResumeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf",
        ".docx"
    };

    private static readonly HashSet<string> AllowedResumeContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    };

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IDataProtector _nricProtector;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<RegisterModel> _logger;
    private readonly IAuditLogger _auditLogger;
    private readonly IRecaptchaValidator _recaptchaValidator;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly IPasswordPolicyService _passwordPolicyService;

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IDataProtectionProvider dataProtectionProvider,
        IWebHostEnvironment environment,
        ILogger<RegisterModel> logger,
        IAuditLogger auditLogger,
        IRecaptchaValidator recaptchaValidator,
        IOptions<RecaptchaOptions> recaptchaOptions,
        IPasswordPolicyService passwordPolicyService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _nricProtector = dataProtectionProvider.CreateProtector("AceJobAgency.Member.Nric.v1");
        _environment = environment;
        _logger = logger;
        _auditLogger = auditLogger;
        _recaptchaValidator = recaptchaValidator;
        _recaptchaOptions = recaptchaOptions.Value;
        _passwordPolicyService = passwordPolicyService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();
    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;
    public bool RecaptchaEnabled => !string.IsNullOrWhiteSpace(_recaptchaOptions.SiteKey) && !string.IsNullOrWhiteSpace(_recaptchaOptions.SecretKey);

    public class InputModel
    {
        [Required]
        [StringLength(100)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [StringLength(20)]
        public string Gender { get; set; } = string.Empty;

        [Required]
        [StringLength(20, MinimumLength = 6)]
        [Display(Name = "NRIC")]
        public string Nric { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [Display(Name = "Email address")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$", ErrorMessage = "Password must include lowercase, uppercase, number, and special character.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "The password and confirmation password do not match.")]
        [Display(Name = "Confirm password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime DateOfBirth { get; set; }

        [Required]
        [Display(Name = "Resume (.docx or .pdf)")]
        public IFormFile? Resume { get; set; }

        [Required]
        [StringLength(2000)]
        [Display(Name = "Who Am I")]
        public string WhoAmI { get; set; } = string.Empty;

        public string RecaptchaToken { get; set; } = string.Empty;
    }

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToPage("/Index");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (RecaptchaEnabled)
        {
            var recaptchaResult = await _recaptchaValidator.ValidateAsync(Input.RecaptchaToken, "register");
            if (!recaptchaResult.IsSuccess)
            {
                ModelState.AddModelError(string.Empty, recaptchaResult.ErrorMessage ?? "reCAPTCHA validation failed.");
                await _auditLogger.LogAsync("RecaptchaFailed", null, Input.Email.Trim(), "Registration blocked by reCAPTCHA validation.");
                return Page();
            }
        }

        if (Input.Resume is null)
        {
            ModelState.AddModelError("Input.Resume", "Resume file is required.");
            return Page();
        }

        if (!IsValidResume(Input.Resume, out var resumeValidationError))
        {
            ModelState.AddModelError("Input.Resume", resumeValidationError);
            return Page();
        }

        var email = Input.Email.Trim();
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser is not null)
        {
            await _auditLogger.LogAsync("RegistrationFailed", existingUser.Id, email, "Registration rejected due to duplicate email.");
            ModelState.AddModelError("Input.Email", "This email is already registered.");
            return Page();
        }

        var resumeStoragePath = Path.Combine(_environment.ContentRootPath, "UserUploads", "Resumes");
        Directory.CreateDirectory(resumeStoragePath);

        var safeOriginalName = Path.GetFileName(Input.Resume.FileName);
        var extension = Path.GetExtension(safeOriginalName);
        var storedFileName = $"{Guid.NewGuid():N}{extension.ToLowerInvariant()}";
        var savedResumePath = Path.Combine(resumeStoragePath, storedFileName);

        await using (var fileStream = new FileStream(savedResumePath, FileMode.CreateNew, FileAccess.Write))
        {
            await Input.Resume.CopyToAsync(fileStream);
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = Input.FirstName.Trim(),
            LastName = Input.LastName.Trim(),
            Gender = Input.Gender.Trim(),
            EncryptedNric = _nricProtector.Protect(Input.Nric.Trim().ToUpperInvariant()),
            DateOfBirth = Input.DateOfBirth.Date,
            WhoAmI = Input.WhoAmI,
            ResumeOriginalFileName = safeOriginalName,
            ResumeStoredFileName = storedFileName,
            ResumeContentType = Input.Resume.ContentType,
            ResumeUploadedAtUtc = DateTime.UtcNow,
            CurrentSessionId = Guid.NewGuid().ToString("N"),
            LastPasswordChangedAtUtc = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, Input.Password);
        if (result.Succeeded)
        {
            await _passwordPolicyService.RecordPasswordHistoryAsync(user);
            _logger.LogInformation("New member account created for {Email}.", email);
            await _auditLogger.LogAsync("RegistrationSuccess", user.Id, email, "User registration succeeded.");
            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToPage("/Index");
        }

        if (System.IO.File.Exists(savedResumePath))
        {
            System.IO.File.Delete(savedResumePath);
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        await _auditLogger.LogAsync("RegistrationFailed", null, email, "Registration failed due to validation or identity errors.");

        return Page();
    }

    private static bool IsValidResume(IFormFile file, out string errorMessage)
    {
        var extension = Path.GetExtension(file.FileName);
        if (!AllowedResumeExtensions.Contains(extension))
        {
            errorMessage = "Only .pdf and .docx files are allowed.";
            return false;
        }

        if (file.Length <= 0 || file.Length > MaxResumeFileSizeBytes)
        {
            errorMessage = "Resume must be between 1 byte and 5 MB.";
            return false;
        }

        if (!AllowedResumeContentTypes.Contains(file.ContentType))
        {
            errorMessage = "Invalid file content type. Please upload a valid .pdf or .docx file.";
            return false;
        }

        errorMessage = string.Empty;
        return true;
    }
}
