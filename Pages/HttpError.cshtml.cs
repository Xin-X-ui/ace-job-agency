using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AceJobAgency.Pages;

public class HttpErrorModel : PageModel
{
    public int HttpStatusCode { get; private set; }

    public string Title { get; private set; } = "Unexpected Error";

    public string Message { get; private set; } = "Something went wrong.";

    public void OnGet(int statusCode)
    {
        HttpStatusCode = statusCode;

        (Title, Message) = statusCode switch
        {
            403 => ("403 - Access Denied", "You do not have permission to access this page."),
            404 => ("404 - Page Not Found", "The page you are looking for does not exist."),
            _ => ($"{statusCode} - Request Error", "The request could not be completed.")
        };
    }
}
