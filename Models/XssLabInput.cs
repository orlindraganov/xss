using System.Web.Mvc;

namespace xss.Models
{
    public class XssLabInput
    {
        // Intentional: permit HTML only on this scanner test input.
        [AllowHtml]
        public string Value { get; set; }
    }
}
