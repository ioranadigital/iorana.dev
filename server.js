// ══════════════════════════════════════════════════════════
//  iorana.dev — Servidor de autenticación segura
//  Node.js + Express (sesiones en memoria)
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

// ── Rate limiter: max 5 intentos / IP / 15 min ────────────
const rateLimiter = new RateLimiterMemory({
  points:   5,
  duration: 15 * 60,
});

// ── Helmet ────────────────────────────────────────────────
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

// X-Robots-Tag en todas las respuestas
app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  next();
});

// ── Parsers ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Sesiones en memoria ───────────────────────────────────
app.use(
  session({
    secret:            process.env.SESSION_SECRET || "cambia-este-secreto",
    resave:            false,
    saveUninitialized: false,
    name:              "iorana.sid",
    cookie: {
      httpOnly: true,
      secure:   process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge:   8 * 60 * 60 * 1000,   // 8 horas
    },
  })
);

// ── Protección de rutas ───────────────────────────────────
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

app.post("/auth/login", async (req, res) => {
  const ip = req.ip;

  try {
    await rateLimiter.consume(ip);
  } catch {
    return res.status(429).json({
      success: false,
      error:   "Demasiados intentos. Espera 15 minutos.",
    });
  }

  const { password } = req.body;
  if (!password || typeof password !== "string") {
    return res.status(400).json({ success: false, error: "Contraseña requerida." });
  }

  const storedHash = process.env.PASSWORD_HASH;
  const match      = await bcrypt.compare(password, storedHash);

  if (!match) {
    await new Promise(r => setTimeout(r, 300));
    return res.status(401).json({ success: false, error: "Contraseña incorrecta." });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ success: false, error: "Error de sesión." });
    req.session.authenticated = true;
    req.session.loginAt       = new Date().toISOString();
    rateLimiter.reward(ip);
    return res.json({ success: true, redirect: "/portal" });
  });
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("iorana.sid");
    res.json({ success: true });
  });
});

app.get("/auth/check", (req, res) => {
  res.json({ authenticated: !!req.session?.authenticated });
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

app.use("/assets", requireAuth, express.static(path.join(__dirname, "public", "assets")));

// ── 404 ───────────────────────────────────────────────────
app.use((req, res) => {
  if (req.session?.authenticated) return res.redirect("/portal");
  res.redirect("/");
});

// ── Arranque ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✓  iorana.dev corriendo en http://localhost:${PORT}`);
  console.log(`   Entorno : ${process.env.NODE_ENV || "development"}`);
  console.log(`   Sesiones: memoria (reinicio limpia sesiones)\n`);
});

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT",  () => process.exit(0));
