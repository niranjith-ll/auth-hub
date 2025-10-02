import express from "express";

const app = express();

// CORS
const allowedOrigins = [
  "https://customer-entra.lodgelink.com",
  "https://admin-entra.lodgelink.com",
  "https://localhost:8000",
  "https://localhost:8002", // 👈 Add this for local development
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-ms-token-aad-access-token"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});

// Health
app.get("/health", (_, res) => res.json({ ok: true }));

// Root and Redirect
app.get("/", (req, res) => {
  const returnTo =
    (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  res.redirect(returnTo);
});

// Login
app.get("/login", (req, res) => {
  const base = process.env.BASE_URL!;
  const returnTo =
    (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  const prompt = (req.query.prompt as string) ?? "login";
  
  const loginUrl = new URL("/.auth/login/aad", base);
  loginUrl.searchParams.set("post_login_redirect_uri", returnTo);

  // Force fresh authentication to prevent login.srf issues
  loginUrl.searchParams.set("prompt", "login");
  
  // Add multiple cache-busting parameters to prevent cached login.srf issues
  loginUrl.searchParams.set("_t", Date.now().toString());
  loginUrl.searchParams.set("_r", Math.random().toString(36).substring(7));
  loginUrl.searchParams.set("force_fresh", "true");
  
  res.redirect(loginUrl.toString());
});

// //  Logout
// app.get("/logout", (req, res) => {
//   const base = process.env.BASE_URL!;
//   const returnTo =
//     (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  
//   // Use logout endpoint with additional parameters to force complete logout
//   const logoutUrl = new URL("/.auth/logout", base);
//   logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);
  
//   // Add parameters to force complete logout and prevent cached login.srf
//   logoutUrl.searchParams.set("_t", Date.now().toString());
//   logoutUrl.searchParams.set("clear_cache", "true");
  
//   res.redirect(logoutUrl.toString());
// });

// Logout - Direct approach that bypasses Azure App Service logout to prevent login.srf
app.get("/logout", (req, res) => {
  const returnTo = (req.query.returnTo as string) ?? "https://customer-entra.lodgelink.com";
  
  // Set headers to prevent caching and clear any stored authentication
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
  
  // Instead of using Azure's logout, redirect directly to Entra ID logout
  // This bypasses the Azure App Service layer that's causing the login.srf issue
  const tenantId = process.env.ENTRA_TENANT_ID;
  const clientId = process.env.CLIENT_ID;
  const logoutUrl = `https://${tenantId}.ciamlogin.com/${tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(returnTo)}&client_id=${clientId}`;
  
  res.redirect(logoutUrl);
});

// Alternative logout - Clear session and redirect without OAuth logout
app.get("/logout-simple", (req, res) => {
  const returnTo = (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  
  // Set aggressive headers to clear all browser data
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage", "executionContexts"');
  
  // Clear any potential session cookies
  res.clearCookie('AppServiceAuthSession');
  res.clearCookie('AppServiceAuthSessionV2');
  res.clearCookie('ARRAffinity');
  res.clearCookie('ARRAffinitySameSite');
  
  // Redirect directly to target app - no OAuth logout
  res.redirect(returnTo);
});

// Handle Azure logout completion redirect - this catches .auth/logout/complete redirects
app.get("/.auth/logout/complete", (req, res) => {
  const returnTo = (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  
  // Set headers to prevent caching
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Redirect to the target application
  res.redirect(returnTo);
});

// Claim Object
type Claim = {
  typ: string;
  val: string;
};

// Updated Client Principal Object
type ClientPrincipal = {
  auth_typ: string; // Authentication type, e.g., "aad"
  name_typ: string; // Claim type used for name
  role_typ: string; // Claim type used for roles
  claims: Claim[];
};

// Me
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
app.get("/api/token", (req, res) => {
  const accessToken = req.header("x-ms-token-aad-access-token");
  if (!accessToken) {
    return res.status(401).json({ error: "no_token" });
  }
  return res.status(200).json({ accessToken });
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

//  Start the server
const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  console.log(`Auth Hub running on :${port}`);
});
