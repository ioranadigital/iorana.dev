// ══════════════════════════════════════════════════════════
//  iorana.dev — Servidor de autenticación segura
//  Multi-usuario + permisos por subdominio
// ══════════════════════════════════════════════════════════

require("dotenv").config();

const express                = require("express");
const session                = require("express-session");
const bcrypt                 = require("bcryptjs");
const helmet                 = require("helmet");
const path                   = require("path");
const { RateLimiterMemory }  = require("rate-limiter-flexible");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── USUARIOS Y PERMISOS ───────────────────────────────────
const USERS = {
  "admin": {
    passwordHash: process.env.ADMIN_HASH || process.env.PASSWORD_HASH,
    tools: ["*"],
    displayName: "Administrador"
  },
  "lara": {
    passwordHash: process.env.LARA_HASH,
    tools: ["n8n.iorana.dev"],
    displayName: "Lara"
  }
};

function userCanAccess(username, host) {
  const user = USERS[username];
  if (!user) return false;
  if (user.tools.includes("*")) return true;
  return user.tools.some(t => host === t || host.endsWith(`.${t}`));
}

function getUserByName(username) {
  return USERS[username] || null;
}

// ── MIDDLEWARES BÁSICOS ───────────────────────────────────
const rateLimiter = new RateLimiterMemory({ points: 5, duration: 15 * 60 });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── SESIONES ──────────────────────────────────────────────
app.use(
  session({
    secret:            process.env.SESSION_SECRET || "cambia-este-secreto",
    resave:            false,
    saveUninitialized: false,
    name:              "iorana.sid",
    cookie: {
      httpOnly: true,
      secure:   process.env.NODE_ENV === "production",
      sameSite: "lax",
      domain:   process.env.COOKIE_DOMAIN || undefined,
      maxAge:   8 * 60 * 60 * 1000,
    },
  })
);

// ── FILTRO DE HOST (EL BLOQUE NUEVO) ──────────────────────
// Este bloque evita que el portal intercepte peticiones de n8n
app.use((req, res, next) => {
  const host = req.headers.host || "";
  const isAuthPath = req.path.startsWith("/auth/");
  
  // Si la petición es para un subdominio (n8n, pdf, etc.) 
  // y NO es una ruta de verificación de login, dejamos que pase de largo.
  if (host !== "iorana.dev" && host !== "www.iorana.dev" && !isAuthPath) {
    return next(); 
  }
  next();
});

// ── PROTECCIÓN RUTAS ──────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  if (req.accepts("html")) return res.redirect("/");
  return res.status(401).json({ error: "No autenticado" });
}

// ── RUTAS PÚBLICAS ────────────────────────────────────────
app.get("/", (req, res) => {
  if (req.session?.authenticated) return res.redirect("/portal");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/auth/login", async (req, res) => {
  const ip = req.ip;
  try { await rateLimiter.consume(ip); } catch {
    return res.status(429).json({ success: false, error: "Demasiados intentos." });
  }

  const { username, password, returnTo } = req.body;
  const user = getUserByName(username?.trim().toLowerCase());

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ success: false, error: "Credenciales inválidas." });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ success: false, error: "Error." });
    req.session.authenticated = true;
    req.session.username      = username.trim().toLowerCase();
    req.session.displayName   = user.displayName;
    req.session.tools         = user.tools;
    
    const redirectTo = returnTo && returnTo.startsWith("https://") ? returnTo : "/portal";
    return res.json({ success: true, redirect: redirectTo });
  });
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("iorana.sid", { domain: process.env.COOKIE_DOMAIN });
    res.json({ success: true });
  });
});

// ── FORWARD AUTH (VERIFY) ─────────────────────────────────
app.get("/auth/verify", (req, res) => {
  const host = req.headers["x-forwarded-host"] || "";
  const proto = req.headers["x-forwarded-proto"] || "https";
  const uri = req.headers["x-forwarded-uri"] || "/";

  if (!req.session?.authenticated) {
    const returnTo = encodeURIComponent(`${proto}://${host}${uri}`);
    return res.redirect(302, `https://iorana.dev/?returnTo=${returnTo}`);
  }

  if (!userCanAccess(req.session.username, host)) {
    return res.status(403).send("<h1>Acceso denegado</h1>");
  }

  res.setHeader("X-Forwarded-User", req.session.username);
  return res.status(200).send("OK");
});

// ── RUTAS PROTEGIDAS ──────────────────────────────────────
app.get("/portal", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "portal.html"));
});

app.get("/api/my-tools", requireAuth, (req, res) => {
  res.json({ tools: req.session.tools, displayName: req.session.displayName });
});

app.use("/assets", express.static(path.join(__dirname, "public", "assets")));

// ── MANEJO DE ERRORES 404 (SOLO PARA IORANA.DEV) ──────────
app.use((req, res) => {
  const host = req.headers.host || "";
  // Solo redirigimos al portal si el error ocurre en el dominio principal
  if (host === "iorana.dev" || host === "www.iorana.dev") {
    return res.redirect(req.session?.authenticated ? "/portal" : "/");
  }
  // Para subdominios (n8n), dejamos que ellos manejen su propio 404
  res.status(404).send("Not Found");
});

app.listen(PORT, () => {
  console.log(`✓ iorana.dev — Autenticador activo en puerto ${PORT}`);
});
