  </form>
</main></body></html>`;

const sendLoginPage = (res, statusCode = 200, hasError = false) => {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  const error = hasError ? '<p class="error">Token tidak cocok. Periksa token di Dokploy lalu coba lagi.</p>' : "";
  res.end(LOGIN_HTML.replace("__ERROR__", error));
};

function createAccessGate(options) {
  const token = String(options?.token ?? "").trim();
  const cookieName = String(options?.cookieName ?? "studio_access").trim() || "studio_access";
  const enabled = Boolean(token);
  const rateLimiter = createRateLimiter(10, 60_000);

  const isAuthorized = (req) => {
    const cookies = parseCookies(req.headers?.cookie);
    return safeCompare(cookies[cookieName] || "", token);
  };

  const handleLogin = (req, res) => {
    const ip = resolveClientIp(req);
    if (rateLimiter.isLimited(ip)) {
      res.statusCode = 429;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Retry-After", "60");
      res.end("Too many failed login attempts. Wait a minute and retry.");
      return;
    }

    let body = "";
    let tooLarge = false;
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 8192) {
        tooLarge = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooLarge) return;
      const submitted = new URLSearchParams(body).get("token") || "";
      if (!safeCompare(submitted, token)) {
        rateLimiter.recordFailure(ip);
        sendLoginPage(res, 401, true);
        return;
      }

      rateLimiter.reset(ip);
      const secure = req.socket?.encrypted || String(req.headers?.["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
      const cookie = `${cookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure ? "; Secure" : ""}`;
      res.statusCode = 303;
      res.setHeader("Set-Cookie", cookie);
      res.setHeader("Location", "/");
      res.setHeader("Cache-Control", "no-store");
      res.end();
    });
  };

  const handleHttp = (req, res) => {
    if (!enabled) return false;
    const pathname = new URL(req.url || "/", "http://localhost").pathname;

    if (pathname === "/studio-login" && req.method === "GET") {
      if (isAuthorized(req)) {
        res.statusCode = 303;
        res.setHeader("Location", "/");
        res.end();
      } else {
        sendLoginPage(res);
      }
      return true;
    }
    if (pathname === "/studio-login" && req.method === "POST") {
      handleLogin(req, res);
      return true;
    }

    if (isAuthorized(req)) return false;
    if (pathname.startsWith("/api/")) {
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "no-store");
      res.end(JSON.stringify({ error: "Studio access token required. Open /studio-login to sign in." }));
      return true;
    }

    res.statusCode = 303;
    res.setHeader("Location", "/studio-login");
    res.setHeader("Cache-Control", "no-store");
    res.end();
    return true;
  };

  const allowUpgrade = (req) => !enabled || isAuthorized(req);
  return { enabled, handleHttp, allowUpgrade };
}

module.exports = { createAccessGate };
