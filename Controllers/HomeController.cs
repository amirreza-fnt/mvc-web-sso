using Microsoft.AspNetCore.Mvc;

namespace SSOLoginService.Web.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        if (User.Identity?.IsAuthenticated == true)
            return Redirect(FrontendUrl);

        return RedirectToAction("Login", "Account");
    }

    public IActionResult Error()
    {
        return View();
    }

    private string FrontendUrl =>
        HttpContext.RequestServices
            .GetRequiredService<IConfiguration>()
            .GetValue<string>("Frontend:Url") ?? "/";
}
