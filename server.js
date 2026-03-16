// ══════════════════════════════════════════════════════════
//  iorana.dev — Servidor de autenticación segura
//  Multi-usuario + permisos por subdominio
// ══════════════════════════════════════════════════════════

require("dotenv").config();

const express               = require("express");
const session               = require("express-session");
const bcrypt                = require("bcryptjs");
const helmet                = require("helmet");
const path                  = require("path");
const { RateLimiterMemory } = require("rate-limiter-flexible");

const app  = express();
const PORT = process.env.PORT || 3000;

// ══════════════════════════════════════════════════════════
//  USUARIOS Y PERMISOS
//  Edita esta sección para añadir/quitar usuarios y accesos.
//
//  Para generar un hash: node hash-password.js
//
//  tools: lista de subdominios permitidos para ese usuario.
//         Usa "*" para acceso total a todos los subdominios.
// ══════════════════════════════════════════════════════════
const USERS = {

  // Administrador — acceso total
  "admin": {
    passwordHash: process.env.ADMIN_HASH || process.env.PASSWORD_HASH,
    tools: ["*"],
    displayName: "Administrador"
  },

  // Ejemplo: usuario con acceso solo a n8n
  "n8n-user": {
    passwordHash: process.env.N8N_USER_HASH,
    tools: ["n8n.iorana.dev"],
    displayName: "Usuario N8N"
  },

  // Ejemplo: usuario con acceso a varias herramientas
  "dev-user": {
    passwordHash: process.env.DEV_USER_HASH,
    tools: ["n8n.iorana.dev", "app.iorana.dev", "tool.iorana.dev"],
    displayName: "Developer"
  },

  // Lara
  "lara": {
    passwordHash: process.env.LARA_HASH,
    tools: ["n8n.iorana.dev"],
    displayName: "Lara"
  },

};

// ── Helpers de permisos ───────────────────────────────────
function userCanAccess(username, host) {
  const user = USERS[username];
  if (!user) return false;
  if (user.tools.includes("*")) return true;
  return user.tools.some(t => host === t || host.endsWith(`.${t}`));
}

function getUserByName(username) {
  return USERS[username] || null;
}

// ══════════════════════════════════════════════════════════
//  RATE LIMITER
// ══════════════════════════════════════════════════════════
const rateLimiter = new RateLimiterMemory({
  points:   5,
  duration: 15 * 60,
});

// ══════════════════════════════════════════════════════════
//  HELMET
// ══════════════════════════════════════════════════════════
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'", "'unsafe-inline'"],
        styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc:    ["'self'", "https://fonts.gstatic.com"],
        imgSrc:     ["'self'", "data:"],
        connectSrc: ["'self'"],
        frameSrc:   ["'none'"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  next();
});

// ── Parsers ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ══════════════════════════════════════════════════════════
//  SESIONES
//  COOKIE_DOMAIN=.iorana.dev comparte la cookie entre
//  todos los subdominios *.iorana.dev
// ══════════════════════════════════════════════════════════
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

// ── Protección rutas internas ─────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  if (req.accepts("html"))        return res.redirect("/");
  return res.status(401).json({ error: "No autenticado" });
}

// ══════════════════════════════════════════════════════════
//  RUTAS PÚBLICAS
// ══════════════════════════════════════════════════════════

app.get("/", (req, res) => {
  if (req.session?.authenticated) return res.redirect("/portal");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── POST /auth/login ──────────────────────────────────────
app.post("/auth/login", async (req, res) => {
  const ip = req.ip;

  try {
    await rateLimiter.consume(ip);
  } catch {
    return res.status(429).json({
      success: false,
      error: "Demasiados intentos. Espera 15 minutos.",
    });
  }

  const { username, password } = req.body;

  if (!username || !password || typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ success: false, error: "Usuario y contraseña requeridos." });
  }

  const user = getUserByName(username.trim().toLowerCase());

  // Hash no configurado para este usuario
  if (!user || !user.passwordHash) {
    await new Promise(r => setTimeout(r, 300));
    return res.status(401).json({ success: false, error: "Usuario o contraseña incorrectos." });
  }

  const match = await bcrypt.compare(password, user.passwordHash);

  if (!match) {
    await new Promise(r => setTimeout(r, 300));
    return res.status(401).json({ success: false, error: "Usuario o contraseña incorrectos." });
  }

  // Guardar returnTo antes de regenerar sesión
  const returnTo = req.body.returnTo || null;

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ success: false, error: "Error de sesión." });
    req.session.authenticated = true;
    req.session.username      = username.trim().toLowerCase();
    req.session.displayName   = user.displayName;
    req.session.tools         = user.tools;
    req.session.loginAt       = new Date().toISOString();
    rateLimiter.reward(ip);
    // Si viene de un subdominio protegido, redirigir de vuelta
    const redirectTo = returnTo && returnTo.startsWith("https://") ? returnTo : "/portal";
    return res.json({ success: true, redirect: redirectTo, displayName: user.displayName });
  });
});

// ── POST /auth/logout ─────────────────────────────────────
app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("iorana.sid", {
      domain: process.env.COOKIE_DOMAIN || undefined,
    });
    res.json({ success: true });
  });
});

// ── GET /auth/check ───────────────────────────────────────
app.get("/auth/check", (req, res) => {
  res.json({
    authenticated: !!req.session?.authenticated,
    username:      req.session?.username || null,
    displayName:   req.session?.displayName || null,
  });
});

// ══════════════════════════════════════════════════════════
//  TRAEFIK FORWARD AUTH
//
//  Traefik llama a este endpoint ANTES de dejar pasar
//  cualquier petición a un subdominio protegido.
//
//  Headers que envía Traefik:
//    X-Forwarded-Host  → subdominio pedido (ej: n8n.iorana.dev)
//    X-Forwarded-Uri   → ruta pedida      (ej: /workflows)
//    X-Forwarded-Proto → https
//
//  Respuestas:
//    200 → Traefik deja pasar la petición ✅
//    401 → Traefik bloquea y redirige al login ❌
// ══════════════════════════════════════════════════════════
app.get("/auth/verify", (req, res) => {
  const host      = req.headers["x-forwarded-host"] || "";
  const proto     = req.headers["x-forwarded-proto"] || "https";
  const uri       = req.headers["x-forwarded-uri"] || "/";

  // Sin sesión → redirigir al login
  if (!req.session?.authenticated) {
    const returnTo = encodeURIComponent(`${proto}://${host}${uri}`);
    return res.redirect(302, `https://iorana.dev/?returnTo=${returnTo}`);
  }

  const username = req.session.username;

  // Sin permiso para este subdominio → 403
  if (!userCanAccess(username, host)) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"/>
        <title>Acceso denegado</title>
        <style>
          body { font-family: sans-serif; background: #0d1f35; color: #c8d8e8;
                 display: flex; align-items: center; justify-content: center;
                 min-height: 100vh; margin: 0; flex-direction: column; gap: 16px; }
          h1   { color: #f5600a; font-size: 24px; }
          p    { color: #6b89a5; font-size: 14px; }
          a    { color: #f5600a; }
        </style>
      </head>
      <body>
        <h1>Acceso denegado</h1>
        <p>No tienes permiso para acceder a <strong>${host}</strong>.</p>
        <p><a href="https://iorana.dev/portal">Volver al portal</a></p>
      </body>
      </html>
    `);
  }

  // ✅ Autenticado y con permiso → pasar
  res.setHeader("X-Forwarded-User", username);
  return res.status(200).send("OK");
});

// ── robots.txt ────────────────────────────────────────────
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /\n");
});

// ══════════════════════════════════════════════════════════
//  RUTAS PROTEGIDAS
// ══════════════════════════════════════════════════════════

app.get("/portal", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "portal.html"));
});

// API: lista de herramientas del usuario actual
app.get("/api/my-tools", requireAuth, (req, res) => {
  res.json({
    username:    req.session.username,
    displayName: req.session.displayName,
    tools:       req.session.tools,
  });
});

app.use("/assets", requireAuth, express.static(path.join(__dirname, "public", "assets")));

// ── 404 ───────────────────────────────────────────────────
app.use((req, res) => {
  if (req.session?.authenticated) return res.redirect("/portal");
  res.redirect("/");
});

// ── Arranque ──────────────────────────────────────────────
app.listen(PORT, () => {
  const userCount = Object.keys(USERS).length;
  console.log(`\n✓  iorana.dev corriendo en http://localhost:${PORT}`);
  console.log(`   Entorno      : ${process.env.NODE_ENV || "development"}`);
  console.log(`   Usuarios     : ${userCount} configurados`);
  console.log(`   Cookie domain: ${process.env.COOKIE_DOMAIN || "mismo dominio"}`);
  console.log(`   Forward auth : https://iorana.dev/auth/verify\n`);
  Object.entries(USERS).forEach(([name, u]) => {
    const tools = u.tools.includes("*") ? "todos los subdominios" : u.tools.join(", ");
    const ok    = u.passwordHash ? "✓" : "⚠ sin hash";
    console.log(`   [${ok}] ${name} (${u.displayName}) → ${tools}`);
  });
  console.log("");
});

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT",  () => process.exit(0));
