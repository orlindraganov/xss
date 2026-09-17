using System.IO;
using System.Web.Mvc;
using xss.Models;

namespace xss.Controllers
{
    public class XssLabController : Controller
    {
        private static readonly object StoreLock = new object();

        protected override void OnAuthorization(AuthorizationContext filterContext)
        {
            base.OnAuthorization(filterContext);

            if (!Request.IsLocal)
            {
                filterContext.Result = HttpNotFound();
            }
        }

        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Reflected(XssLabInput input)
        {
            return View(input);
        }

        [HttpGet]
        [ValidateInput(false)]
        public ActionResult ContentResult()
        {
            var value = Request.Unvalidated.QueryString["value"] ?? string.Empty;

            // Intentional CWE-79: query-string input reaches an HTML ContentResult without encoding.
            return Content("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" />"
                + "<title>Intentional XSS Lab - ContentResult</title></head><body>"
                + "<h1>C# ContentResult XSS</h1>"
                + "<p><strong>WARNING: Deliberately vulnerable scanner fixture. Local testing only. Never deploy publicly.</strong></p>"
                + "<div id=\"vulnerable-output\">" + value + "</div></body></html>", "text/html");
        }

        [HttpGet]
        [ValidateInput(false)]
        public ActionResult ResponseWrite()
        {
            var value = Request.Unvalidated.QueryString["value"] ?? string.Empty;
            Response.ContentType = "text/html";
            Response.Write("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" />"
                + "<title>Intentional XSS Lab - Response.Write</title></head><body>"
                + "<h1>C# Response.Write XSS</h1>"
                + "<p><strong>WARNING: Deliberately vulnerable scanner fixture. Local testing only. Never deploy publicly.</strong></p>"
                + "<div id=\"vulnerable-output\">");

            // Intentional CWE-79: query-string input is written directly to an HTML response.
            Response.Write(value);
            Response.Write("</div></body></html>");
            return new EmptyResult();
        }

        [HttpGet]
        public ActionResult Stored()
        {
            var path = Server.MapPath("~/App_Data/xss-lab.txt");
            string value;

            lock (StoreLock)
            {
                value = System.IO.File.Exists(path) ? System.IO.File.ReadAllText(path) : string.Empty;
            }

            return View(new XssLabInput { Value = value });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Stored(XssLabInput input)
        {
            var path = Server.MapPath("~/App_Data/xss-lab.txt");

            lock (StoreLock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                System.IO.File.WriteAllText(path, input.Value ?? string.Empty);
            }

            return RedirectToAction("Stored");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ClearStored()
        {
            lock (StoreLock)
            {
                System.IO.File.Delete(Server.MapPath("~/App_Data/xss-lab.txt"));
            }

            return RedirectToAction("Stored");
        }

        [HttpGet]
        public ActionResult Dom()
        {
            return View();
        }
    }
}
