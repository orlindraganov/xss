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
