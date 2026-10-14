const crypto = require("node:crypto");

const parseCookies = (header) => {
  const raw = typeof header === "string" ? header : "";
  if (!raw.trim()) return {};

  const out = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;

    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;

    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }

  return out;
};

const safeCompare = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string") return false;

  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");

  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
};

const createRateLimiter = (maxAttempts = 10, windowMs = 60_000) => {
  const attempts = new Map();

  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of attempts) {
      if (now - entry.start > windowMs) attempts.delete(key);
    }
  }, windowMs);

  cleanup.unref();

  return {
    isLimited(ip) {
      const entry = attempts.get(ip);
      return Boolean(entry && entry.count >= maxAttempts);
    },

    recordFailure(ip) {
      const now = Date.now();
      const entry = attempts.get(ip);

      if (!entry || now - entry.start > windowMs) {
        attempts.set(ip, { count: 1, start: now });
        return;
      }

      entry.count++;
    },

    reset(ip) {
      attempts.delete(ip);
    },
  };
};

const resolveClientIp = (req) => {
  if (process.env.TRUSTED_PROXY === "1") {
    const forwarded = req.headers?.["x-forwarded-for"];
    if (typeof forwarded === "string") {
      const first = forwarded.split(",")[0]?.trim();
      if (first) return first;
    }
  }

  return req.socket?.remoteAddress || "unknown";
};

const LOGIN_HTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Masuk ke Hermes3D</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #10131a;
      color: #eef2f8;
      font: 16px system-ui, sans-serif;
    }
    main {
      width: min(92vw, 420px);
      padding: 32px;
      border: 1px solid #303744;
      border-radius: 18px;
      background: #191e28;
      box-shadow: 0 20px 60px #0005;
    }
    h1 { margin: 0 0 8px; font-size: 24px; }
    p { margin: 0 0 24px; color: #abb5c5; line-height: 1.5; }
    label { display: block; margin-bottom: 8px; font-weight: 600; }
    input {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid #485264;
      border-radius: 10px;
      background: #0e1219;
      color: white;
      font: inherit;
    }
    button {
      width: 100%;
      margin-top: 16px;
      padding: 12px;
      border: 0;
      border-radius: 10px;
      background: #f28c28;
      color: #171717;
      font: 600 16px system-ui, sans-serif;
      cursor: pointer;
    }
    .error { margin: 0 0 16px; color: #ff9b9b; }
  </style>
</head>
<body>
  <main>
    <h1>Hermes3D</h1>
    <p>Masukkan Studio Access Token untuk membuka workspace.</p>
    __ERROR__
    <form method="post" action="/studio-login" autocomplete="on">
      <label for="token">Studio Access Token</label>
      <input
        id="token"
        name="token"
        type="password"
        autocomplete="current-password"
        required
        autofocus
      >
      <button type="submit">Masuk</button>
    </form>
  </main>
</body>
</html>`;

const sendLoginPage = (res, statusCode = 200, hasError = false) => {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );

  const error = hasError
    ? '<p class="error">Token tidak cocok. Periksa token di Dokploy lalu coba lagi.</p>'
    : "";

  res.end(LOGIN_HTML.replace("__ERROR__", error));
};

function createAccessGate(options) {
  const token = String(options?.token ?? "").trim();
  const cookieName =
    String(options?.cookieName ?? "studio_access").trim() || "studio_access";
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
      res.end("Terlalu banyak percobaan gagal. Tunggu satu menit lalu coba lagi.");
      return;
    }

    let body = "";
    let tooLarge = false;

    req.on("data", (chunk) => {
      body += chunk.toString("utf8");

      if (body.length > 8192) {
        tooLarge = true;
        res.statusCode = 413;
        res.end("Permintaan terlalu besar.");
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

      const forwardedProto = String(
        req.headers?.["x-forwarded-proto"] || ""
      )
        .split(",")[0]
        .trim();

      const secure = Boolean(req.socket?.encrypted) || forwardedProto === "https";
      const cookie =
        `${cookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800` +
        (secure ? "; Secure" : "");

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
      res.end(
        JSON.stringify({
          error: "Studio access token required. Open /studio-login to sign in.",
        })
      );
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
