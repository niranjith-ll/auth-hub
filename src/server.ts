import express from "express";

const app = express();

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  next();
});

// Health
app.get("/health", (_, res) => res.json({ ok: true }));

// Login
// app.get("/login", (req, res) => {
//   const base = process.env.BASE_URL!;
//   const returnTo =
//     (req.query.returnTo as string) ?? "https://app.lodgelink.com";
//   const loginUrl = new URL("/.auth/login/aad", base);
//   loginUrl.searchParams.set("post_login_redirect_uri", returnTo);
//   res.redirect(loginUrl.toString());
// });

// Login
app.get("/login", (req, res) => {
  const base = process.env.BASE_URL!;
  const referer = req.get("Referer");

  // Validate referer against *.lodgelink.com
  const isValidReferer =
    referer &&
    /^https:\/\/([a-z0-9-]+\.)?lodgelink\.com(\/|$)/i.test(referer);

  const returnTo =
    (req.query.returnTo as string) ??
    (isValidReferer ? referer : "https://app.lodgelink.com");

  const loginUrl = new URL("/.auth/login/aad", base);
  loginUrl.searchParams.set("post_login_redirect_uri", returnTo);

  console.log("Redirecting to:", loginUrl.toString());
  res.redirect(loginUrl.toString());
});


//  Logout
app.get("/logout", (req, res) => {
  const base = process.env.BASE_URL!;
  const returnTo =
    (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  const logoutUrl = new URL("/.auth/logout", base);
  logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);
  res.redirect(logoutUrl.toString());
});

// Me Object
type ClientPrincipal = {
  identityProvider: string;
  userId: string;
  userDetails: string;
  userRoles: string[];
  claims?: { typ: string; val: string }[];
};

// Authnetication user
app.get("/api/me", (req, res) => {
  const b64 = req.header("x-ms-client-principal");
  if (!b64) {
    return res.status(200).json({ authenticated: false });
  }

  const decoded = Buffer.from(b64, "base64").toString("utf8");
  const principal = JSON.parse(decoded) as ClientPrincipal;

  return res.status(200).json({ authenticated: true, principal });
});

// Access Token
app.get("/api/token", async (req, res) => {
  try {
    // Trigger App Service to refresh tokens
    await fetch(`${process.env.BASE_URL}/.auth/refresh`, {
      method: "GET",
      headers: {
        Cookie: req.headers.cookie || "", // Pass session cookie to preserve auth
      },
    });

    // Read the updated access token from request headers
    const accessToken = req.header("x-ms-token-aad-access-token");
    if (!accessToken) {
      return res.status(401).json({ error: "no_token" });
    }

    return res.status(200).json({ accessToken });
  } catch (err) {
    console.error("Token refresh error:", err);
    return res.status(500).json({ error: "refresh_exception" });
  }
});

// OBO Token
app.get("/api/obotoken", async (req, res) => {
  const idToken = req.header("x-ms-token-aad-id-token");
  if (!idToken) {
    return res.status(401).json({ error: "no_token" });
  }

  // Exchange tokens
  const exchange = `https://${process.env.ENTRA_TENANT_ID}.ciamlogin.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`;

  // On-behalf-of (OBO) flow
  const params = new URLSearchParams({
    client_id: `${process.env.CLIENT_ID}`,
    client_secret: `${process.env.CLIENT_SECRET}`,
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    requested_token_use: "on_behalf_of",
    assertion: idToken,
    scope: `${process.env.CLIENT_ID}/user_impersonation`, // 👈 GUID form for self-OBO
  });

  try {
    // Make the request
    const response = await fetch(exchange, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });
    // Get the response
    const data = await response.json();
    if (!response.ok) {
      return res.status(500).json({ error: "obo_failed", details: data });
    }
    return res.json({ accessToken: data.access_token });
  } catch (err) {
    // Handle errors
    console.error("OBO exception:", err);
    return res.status(500).json({ error: "obo_exception" });
  }
});

// Access Token
app.get("/api/idtoken", (req, res) => {
  const idToken = req.header("x-ms-token-aad-id-token");
  if (!idToken) {
    return res.status(401).json({ error: "no_token" });
  }
  return res.status(200).json({ idToken });
});

// Session info
app.get("/api/session", (req, res) => {
  const principalHeader = req.header("x-ms-client-principal");
  const expiresOn = req.header("x-ms-token-aad-expires-on");

  if (!principalHeader || !expiresOn) {
    return res.status(401).json({ authenticated: false });
  }

  const principal = JSON.parse(Buffer.from(principalHeader, "base64").toString("utf8"));
  return res.json({
    authenticated: true,
    expiresOn: Number(expiresOn) * 1000,
    principal,
  });
});


//  Start the server
const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  console.log(`Auth Hub running on :${port}`);
});
