// =============================================
// Cybersecurity Tool - Backend (Node.js/Express)
// =============================================
// Run: npm install && node server.js

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// ------------------------------------------
// Common weak passwords list
// ------------------------------------------
const COMMON_PASSWORDS = [
  "password","123456","password1","qwerty","abc123",
  "111111","letmein","monkey","dragon","master",
  "123456789","password123","iloveyou","welcome","admin",
  "login","hello","sunshine","princess","shadow"
];

// ------------------------------------------
// POST /api/check-password
// Body: { password: string }
// Returns: strength analysis object
// ------------------------------------------
app.post("/api/check-password", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  // Run checks
  const checks = {
    hasMinLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecial: /[^A-Za-z0-9]/.test(password),
    isNotCommon: !COMMON_PASSWORDS.includes(password.toLowerCase()),
  };

  // Calculate character pool size
  let poolSize = 0;
  if (checks.hasLowercase) poolSize += 26;
  if (checks.hasUppercase) poolSize += 26;
  if (checks.hasNumber) poolSize += 10;
  if (checks.hasSpecial) poolSize += 32;

  // Calculate entropy in bits
  const entropy = poolSize > 0
    ? Math.round(password.length * Math.log2(poolSize))
    : 0;

  // Estimate crack time (assuming 10 billion guesses/sec)
  const crackTime = estimateCrackTime(entropy);

  // Overall strength score (0-5)
  const score = Object.values(checks).filter(Boolean).length;
  const strength = getStrengthLabel(score, entropy);

  // Generate tips
  const tips = generateTips(checks, entropy);

  res.json({
    checks,
    entropy,
    poolSize,
    length: password.length,
    crackTime,
    strength,
    score,
    tips,
  });
});

// ------------------------------------------
// POST /api/check-breach
// Body: { password: string }
// Checks HaveIBeenPwned using k-anonymity
// ------------------------------------------
app.post("/api/check-breach", async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    // SHA-1 hash the password
    const sha1 = crypto.createHash("sha1")
      .update(password)
      .digest("hex")
      .toUpperCase();

    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    // Call HaveIBeenPwned API (only sends first 5 chars of hash)
    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`
    );

    if (!response.ok) {
      throw new Error("HaveIBeenPwned API error");
    }

    const text = await response.text();
    const lines = text.split("\n");
    const match = lines.find((line) => line.startsWith(suffix));

    if (match) {
      const count = parseInt(match.split(":")[1]);
      res.json({ breached: true, count });
    } else {
      res.json({ breached: false, count: 0 });
    }
  } catch (err) {
    res.status(500).json({ error: "Could not reach breach database" });
  }
});

// ------------------------------------------
// GET /api/generate-password
// Returns a secure random password
// ------------------------------------------
app.get("/api/generate-password", (req, res) => {
  const chars =
    "abcdefghijklmnopqrstuvwxyz" +
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "0123456789" +
    "!@#$%^&*()_+-=[]{}";

  let password = "";
  const bytes = crypto.randomBytes(16);

  for (const byte of bytes) {
    password += chars[byte % chars.length];
  }

  res.json({ password });
});

// ------------------------------------------
// Helper functions
// ------------------------------------------
function estimateCrackTime(bits) {
  const attempts = Math.pow(2, bits);
  const perSec = 1e10; // 10 billion/sec
  const secs = attempts / perSec;

  if (secs < 1) return "Instant";
  if (secs < 60) return `${Math.round(secs)} seconds`;
  if (secs < 3600) return `${Math.round(secs / 60)} minutes`;
  if (secs < 86400) return `${Math.round(secs / 3600)} hours`;
  if (secs < 31536000) return `${Math.round(secs / 86400)} days`;
  if (secs < 3.154e10) return `${Math.round(secs / 31536000)} years`;
  return "Centuries";
}

function getStrengthLabel(score, entropy) {
  if (entropy < 28 || score <= 2) return "Very Weak";
  if (entropy < 36 || score <= 3) return "Weak";
  if (entropy < 50 || score <= 4) return "Fair";
  if (entropy < 60) return "Strong";
  return "Very Strong";
}

function generateTips(checks, entropy) {
  const tips = [];
  if (!checks.hasMinLength) tips.push("Use at least 8 characters.");
  if (!checks.hasUppercase) tips.push("Add uppercase letters (A-Z).");
  if (!checks.hasLowercase) tips.push("Add lowercase letters (a-z).");
  if (!checks.hasNumber) tips.push("Include at least one number.");
  if (!checks.hasSpecial) tips.push("Add special characters like @, #, $.");
  if (!checks.isNotCommon) tips.push("Avoid common passwords like 'password123'.");
  if (entropy >= 60 && Object.values(checks).every(Boolean)) {
    tips.push("Excellent! Store it in a password manager.");
  }
  return tips;
}

app.listen(PORT, () => {
  console.log(`✅ Backend running at http://localhost:${PORT}`);
});
