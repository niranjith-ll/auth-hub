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
  const loginUrl = new URL("/.auth/login/aad", base);
  loginUrl.searchParams.set("post_login_redirect_uri", returnTo);
  res.redirect(loginUrl.toString());
});

//  Logout
app.get("/logout", (req, res) => {
  const base = process.env.BASE_URL!;
  const returnTo =
    (req.query.returnTo as string) ?? "https://app.lodgelink.com";
  const logoutUrl = new URL("/.auth/logout", base);
  logoutUrl.searchParams.set("post_logout_redirect_uri", "https://customer-entra.lodgelink.com/en/dashboard");
  res.redirect(logoutUrl.toString());
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