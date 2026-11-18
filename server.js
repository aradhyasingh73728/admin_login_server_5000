
import { createClient } from "@supabase/supabase-js";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

dotenv.config();

import crypto from "crypto";

console.log("ADMIN JWT CHECK:", {
  length: process.env.JWT_SECRET?.length,
  fingerprint: crypto
    .createHash("sha256")
    .update(process.env.JWT_SECRET || "")
    .digest("hex")
    .slice(0, 10),
});

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// ENVIRONMENT VALIDATION
// ============================================================

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "ADMIN_ID",
  "ADMIN_PASSWORD",
  "JWT_SECRET",
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

// ============================================================
// SUPABASE CONNECTION
// ============================================================

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

// ============================================================
// GET CURRENT ADMIN TOKEN VERSION
// ============================================================

async function getAdminTokenVersion() {
  const { data, error } = await supabase
    .from("admin_token_state")
    .select("token_version")
    .eq("id", 1)
    .single();

  if (error || !data) {
    console.error("TOKEN STATE ERROR:", error?.message);
    throw new Error("Admin token state unavailable");
  }

  if (
    !Number.isInteger(data.token_version) ||
    data.token_version < 0
  ) {
    throw new Error("Invalid admin token version");
  }

  return data.token_version;
}

// ============================================================
// DEVICE NAME DETECTION
// ============================================================

function getDeviceName(userAgent) {
  const ua = userAgent || "";

  let browser = "Unknown Browser";
  let device = "Unknown Device";

  if (ua.includes("Edg/")) {
    browser = "Edge";
  } else if (ua.includes("Chrome/")) {
    browser = "Chrome";
  } else if (ua.includes("Firefox/")) {
    browser = "Firefox";
  } else if (ua.includes("Safari/")) {
    browser = "Safari";
  }

  if (ua.includes("Windows")) {
    device = "Windows PC";
  } else if (ua.includes("Android")) {
    device = "Android";
  } else if (ua.includes("iPhone")) {
    device = "iPhone";
  } else if (ua.includes("Mac OS")) {
    device = "Mac";
  } else if (ua.includes("Linux")) {
    device = "Linux";
  }

  return `${device} - ${browser}`;
}

// ============================================================
// TRUST PROXY
// ============================================================

app.set("trust proxy", 1);

// ============================================================
// CORS CONFIGURATION
// ============================================================


const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",

  "https://bgmi-admin-panel-9eei.onrender.com",
  "https://free-fire-admin-panel.onrender.com",

  "https://bgmi-admin-panel.aradhyasingh-73728.workers.dev",

  "https://bgmi-admin-panel.tournament-esports.workers.dev"
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(
      new Error(`CORS blocked for origin: ${origin}`)
    );
  },

  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());

// ============================================================
// LOGIN RATE LIMITING
// ============================================================

const loginAttempts = {};

app.use("/admin/login", (req, res, next) => {
  const ip =
    req.ip ||
    req.connection?.remoteAddress ||
    "unknown";

  const now = Date.now();

  loginAttempts[ip] = loginAttempts[ip] || [];

  loginAttempts[ip] = loginAttempts[ip].filter(
    (time) => now - time < 15 * 60 * 1000
  );

  if (loginAttempts[ip].length >= 5) {
    return res.status(429).json({
      success: false,
      message: "Too many login attempts. Try after 15 min.",
    });
  }

  loginAttempts[ip].push(now);
  next();
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/", (req, res) => {
  res.json({
    status: "BGMI Admin Server LIVE",
    timestamp: new Date().toISOString(),

    endpoints: [
      { path: "/admin/login", method: "POST" },
      { path: "/admin/verify", method: "GET" },
      { path: "/admin/logout-all", method: "POST" },
    ],
  });
});

// ============================================================
// ADMIN LOGIN + CREATE INDIVIDUAL SESSION
// ============================================================

app.post("/admin/login", async (req, res) => {
  try {
    const { id, password } = req.body;

    if (
      id !== process.env.ADMIN_ID ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid admin credentials.",
      });
    }

    // Current global token version
    const tokenVersion = await getAdminTokenVersion();

    // Generate unique session ID
    const sessionId = randomUUID();

    // Device information
    const userAgent = req.get("user-agent") || "Unknown";

    const deviceName = getDeviceName(userAgent);

    const ipAddress = req.ip || null;

    // Save new session in Supabase
    const { error: sessionError } = await supabase
      .from("admin_sessions")
      .insert({
        id: sessionId,
        admin_id: process.env.ADMIN_ID,
        device_name: deviceName,
        user_agent: userAgent,
        ip_address: ipAddress,
        last_activity_at: new Date().toISOString(),
        is_revoked: false,
      });

    if (sessionError) {
      console.error("SESSION INSERT ERROR:", sessionError.message);

      return res.status(503).json({
        success: false,
        message: "Unable to create admin session.",
      });
    }

    // Generate JWT with session ID
    const token = jwt.sign(
      {
        role: "admin",
        id: process.env.ADMIN_ID,
        ver: tokenVersion,
        sid: sessionId,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.status(200).json({
      success: true,
      message: "Admin login successful.",
      token,
      session: {
        id: sessionId,
        device_name: deviceName,
      },
    });

  } catch (error) {
    console.error("ADMIN LOGIN ERROR:", error.message);

    return res.status(503).json({
      success: false,
      message: "Admin authentication service unavailable.",
    });
  }
});

// ============================================================
// ADMIN VERIFY + INDIVIDUAL SESSION CHECK
// GET /admin/verify
// ============================================================

app.get("/admin/verify", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication token required.",
      });
    }

    const token = authHeader.split(" ")[1];

    // Verify JWT
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    // Verify admin identity
    if (
      decoded.role !== "admin" ||
      decoded.id !== process.env.ADMIN_ID
    ) {
      return res.status(403).json({
        success: false,
        message: "Admin access denied.",
      });
    }

    // Verify global token version
    const currentVersion = await getAdminTokenVersion();

    if (
      !Number.isInteger(decoded.ver) ||
      decoded.ver !== currentVersion
    ) {
      return res.status(401).json({
        success: false,
        message: "Old or revoked admin token. Login again.",
      });
    }

    // Verify individual session ID
    if (!decoded.sid) {
      return res.status(401).json({
        success: false,
        message: "Session ID missing. Login again.",
      });
    }

    const { data: session, error: sessionError } =
      await supabase
        .from("admin_sessions")
        .select("id, admin_id, is_revoked")
        .eq("id", decoded.sid)
        .eq("admin_id", decoded.id)
        .maybeSingle();

    if (sessionError) {
      console.error("SESSION VERIFY ERROR:", sessionError.message);

      return res.status(503).json({
        success: false,
        message: "Session verification unavailable.",
      });
    }

    if (!session || session.is_revoked) {
      return res.status(401).json({
        success: false,
        message: "This admin session has been revoked.",
      });
    }

    // Update last activity
    const { error: activityError } = await supabase
      .from("admin_sessions")
      .update({
        last_activity_at: new Date().toISOString(),
      })
      .eq("id", decoded.sid)
      .eq("admin_id", decoded.id)
      .eq("is_revoked", false);

    if (activityError) {
      console.error("ACTIVITY UPDATE ERROR:", activityError.message);

      return res.status(503).json({
        success: false,
        message: "Unable to update session activity.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Admin session verified.",
      admin: {
        id: decoded.id,
        role: decoded.role,
      },
      session: {
        id: decoded.sid,
        active: true,
      },
    });

  } catch (error) {
    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired admin token.",
      });
    }

    console.error("ADMIN VERIFY ERROR:", error.message);

    return res.status(503).json({
      success: false,
      message: "Admin verification service unavailable.",
    });
  }
});

// ============================================================
// LOGOUT ALL ADMIN SESSIONS
// POST /admin/logout-all
// ============================================================

app.post("/admin/logout-all", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (
      decoded.role !== "admin" ||
      decoded.id !== process.env.ADMIN_ID
    ) {
      return res.status(403).json({
        success: false,
        message: "Admin access denied.",
      });
    }

    const currentVersion = await getAdminTokenVersion();

    if (
      !Number.isInteger(decoded.ver) ||
      decoded.ver !== currentVersion
    ) {
      return res.status(401).json({
        success: false,
        message: "Old or revoked admin token.",
      });
    }

    // Increment global token version
    const { data, error } = await supabase
      .from("admin_token_state")
      .update({
        token_version: currentVersion + 1,
        updated_at: new Date().toISOString(),
      })
      .eq("id", 1)
      .eq("token_version", currentVersion)
      .select("token_version")
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!data) {
      return res.status(409).json({
        success: false,
        message: "Token version changed. Please try again.",
      });
    }

    // Mark all admin sessions revoked
    const { error: revokeError } = await supabase
      .from("admin_sessions")
      .update({
        is_revoked: true,
        revoked_at: new Date().toISOString(),
      })
      .eq("admin_id", process.env.ADMIN_ID)
      .eq("is_revoked", false);

    if (revokeError) {
      console.error("SESSION REVOKE ERROR:", revokeError.message);
    }

    return res.status(200).json({
      success: true,
      message: "All admin sessions revoked. Login again.",
    });

  } catch (error) {
    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired admin token.",
      });
    }

    console.error("LOGOUT ALL ERROR:", error.message);

    return res.status(503).json({
      success: false,
      message: "Unable to revoke admin sessions.",
    });
  }
});

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err.message);

  if (err.message?.includes("CORS blocked")) {
    return res.status(403).json({
      success: false,
      message: err.message,
    });
  }

  return res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// ============================================================
// SERVER START
// ============================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BGMI Admin Server LIVE on port ${PORT}`);
});
