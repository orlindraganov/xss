# xss

## Intentional C# XSS scanner fixtures

This .NET Framework 4.8 / ASP.NET MVC lab contains deliberately vulnerable CWE-79 examples. Use an isolated local IIS Express environment and a disposable browser profile without sensitive sessions. Never deploy publicly or alongside sensitive applications.

The XssLab controller rejects nonlocal requests with HTTP 404. This is not a sandbox: injected JavaScript executes with the application's origin privileges. Do not expose the app through a local reverse proxy or tunnel, which can make remote requests appear local.

### C#-only source-to-sink patterns

Both fixtures are in `Controllers/XssLabController.cs`; neither uses a Razor view, `Html.Raw`, model binding, or persistence.

| Endpoint | Source | Intentional sink |
| --- | --- | --- |
| `/XssLab/ContentResult?value=...` | `Request.Unvalidated.QueryString["value"]` | Input concatenated into HTML and returned with `Content(..., "text/html")` |
| `/XssLab/ResponseWrite?value=...` | `Request.Unvalidated.QueryString["value"]` | `Response.Write(value)` after setting `Response.ContentType` to `text/html` |

Each action uses `[HttpGet]` and action-scoped `[ValidateInput(false)]`. The explicit `Request.Unvalidated.QueryString` read bypasses ASP.NET deferred validation for the test input; the MVC attribute alone does not bypass validation on direct `Request.QueryString` reads. Application-wide request validation is unchanged. The ResponseWrite action returns `EmptyResult` so MVC does not attempt view rendering. Existing reflected Razor, stored Razor, and DOM-based examples remain available from `/XssLab`.

### Manual verification

Start the app in Visual Studio with IIS Express. Open `/XssLab` for links, or append these paths to the local application origin:

	/XssLab/ContentResult?value=%3Cimg%20src%3Dx%20onerror%3Dalert(%27xss-lab%27)%3E
	/XssLab/ResponseWrite?value=%3Cimg%20src%3Dx%20onerror%3Dalert(%27xss-lab%27)%3E

These URLs supply the harmless demonstration payload `<img src=x onerror=alert('xss-lab')>`. Each should display an alert in a browser. The responses should have content type `text/html` and contain the literal, unencoded payload inside `vulnerable-output`.

Also check each endpoint with `?value=plain-text` and with no query string. Both should return HTTP 200 and display a warning; empty input should not cause an error. Nonlocal requests should receive HTTP 404. HTTP response tests verify the sink output, but browser execution must be checked separately.

### Scanner interpretation

These are calibration cases, not guaranteed Polaris findings. Verify that C# analysis ran, included `XssLabController.cs`, and enabled the relevant security checks. Detection of these direct C# flows but not the original Razor examples can help distinguish MVC/Razor modeling limitations from missing C# scan coverage. Do not suppress the intentional findings during scanner assessment.
