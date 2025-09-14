import express from "express";

const app = express();

// --- util: CORS for credentialed calls from your apps ---
const allowed = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);



app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }
    next();
});

// --- health ---
app.get("/health", (_, res) => res.json({ ok: true }));

// --- login: send to Easy Auth login endpoint ---
app.get("/login", (req, res) => {
    const base = process.env.BASE_URL!;
    const returnTo = (req.query.returnTo as string) ?? "https://app.lodgelink.com";
    const loginUrl = new URL("/.auth/login/aad", base);
    loginUrl.searchParams.set("post_login_redirect_url", returnTo);
    res.redirect(loginUrl.toString());
});

// --- logout: send to Easy Auth logout endpoint ---
app.get("/logout", (req, res) => {
    const base = process.env.BASE_URL!;
    const returnTo = (req.query.returnTo as string) ?? "https://app.lodgelink.com";
    const logoutUrl = new URL("/.auth/logout", base);
    logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);
    res.redirect(logoutUrl.toString());
});

// --- who am I: read Easy Auth principal header ---
type ClientPrincipal = {
    identityProvider: string;
    userId: string;
    userDetails: string;
    userRoles: string[];
    claims?: { typ: string; val: string }[];
};

app.get("/api/me", (req, res) => {

    const b64 = req.header("x-ms-client-principal");
    if (!b64) {
        return res.status(200).json({ authenticated: false });
    }

    const decoded = Buffer.from(b64, "base64").toString("utf8");
    const principal = JSON.parse(decoded) as ClientPrincipal;

    return res.status(200).json({ authenticated: true, principal });
});

// --- optional: return an access token (if Easy Auth injects it) ---
app.get("/api/token", (req, res) => {
    const accessToken = req.header("x-ms-token-aad-access-token");
    if (!accessToken) {
        return res.status(401).json({ error: "no_token" });
    }
    return res.status(200).json({ accessToken });
});

// --- start ---
const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
    console.log(`Auth Hub running on :${port}`);
});
