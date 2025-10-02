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

// Logout - Properly clears Azure App Service session to invalidate tokens
app.get("/logout", (req, res) => {
  const returnTo = (req.query.returnTo as string) ?? "https://customer-entra.lodgelink.com";
  
  // Set headers to prevent caching and clear any stored authentication
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
  
  // Use Azure App Service logout endpoint to properly clear the server-side session
  // This is CRITICAL to invalidate the tokens that /api/token returns
  const base = process.env.BASE_URL!;
  const logoutUrl = new URL("/.auth/logout", base);
  logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);
  
  console.log('🔴 LOGOUT: Redirecting to Azure logout:', logoutUrl.toString());
  res.redirect(logoutUrl.toString());
});

// Logout handler that performs the actual logout and prevents login.srf loop
app.get("/logout-handler", (req, res) => {
  const returnTo = (req.query.returnTo as string) ?? "https://customer-entra.lodgelink.com";
  
  // Set aggressive headers to clear all browser data
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage", "executionContexts"');
  
  // Clear all potential Azure App Service cookies
  res.clearCookie('AppServiceAuthSession');
  res.clearCookie('AppServiceAuthSessionV2');
  res.clearCookie('ARRAffinity');
  res.clearCookie('ARRAffinitySameSite');
  res.clearCookie('ARRAffinitySameSiteV2');
  
  // Return a page that performs logout via JavaScript and then redirects
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Logging out...</title>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background: #f5f5f5;
        }
        .container {
          text-align: center;
          background: white;
          padding: 2rem;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .spinner {
          border: 3px solid #f3f3f3;
          border-top: 3px solid #0078d4;
          border-radius: 50%;
          width: 30px;
          height: 30px;
          animation: spin 1s linear infinite;
          margin: 0 auto 1rem;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="spinner"></div>
        <h2>Logging out...</h2>
        <p>Please wait while we log you out securely.</p>
        <script>
          // Clear all browser storage
          if (window.localStorage) {
            localStorage.clear();
          }
          if (window.sessionStorage) {
            sessionStorage.clear();
          }
          
          // Clear any cookies we can access
          document.cookie.split(";").forEach(function(c) { 
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
          });
          
          // Perform logout via iframe to avoid redirect loops
          function performLogout() {
            const tenantId = '${process.env.ENTRA_TENANT_ID}';
            const clientId = '${process.env.CLIENT_ID}';
            
            // Create hidden iframe to perform logout
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = \`https://\${tenantId}.ciamlogin.com/\${tenantId}/oauth2/v2.0/logout?client_id=\${clientId}\`;
            
            iframe.onload = function() {
              // After iframe loads, redirect to target
              setTimeout(() => {
                window.location.href = '${returnTo}';
              }, 1000);
            };
            
            iframe.onerror = function() {
              // If iframe fails, still redirect
              setTimeout(() => {
                window.location.href = '${returnTo}';
              }, 1000);
            };
            
            document.body.appendChild(iframe);
          }
          
          // Start logout process after a short delay
          setTimeout(performLogout, 500);
        </script>
      </div>
    </body>
    </html>
  `);
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

// Debug endpoint to check authentication status
app.get("/api/auth-status", (req, res) => {
  const accessToken = req.header("x-ms-token-aad-access-token");
  const idToken = req.header("x-ms-token-aad-id-token");
  const principal = req.header("x-ms-client-principal");
  
  res.json({
    hasAccessToken: !!accessToken,
    hasIdToken: !!idToken,
    hasPrincipal: !!principal,
    isAuthenticated: !!(accessToken || idToken || principal),
    timestamp: new Date().toISOString()
  });
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
