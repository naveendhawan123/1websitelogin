const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const redis = Redis.fromEnv();

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashOtp(email, code) {
  return crypto
    .createHmac("sha256", process.env.OTP_HMAC_SECRET)
    .update(`${email}:${code}`)
    .digest("hex");
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const { email, code } = req.body || {};

    const cleanEmail = normalizeEmail(email);
    const cleanCode = String(code || "").trim();

    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        error: "Invalid email address."
      });
    }

    if (!/^\d{6}$/.test(cleanCode)) {
      return res.status(400).json({
        error: "Enter the 6-digit OTP."
      });
    }

    const otpKey = `otp:${cleanEmail}`;

    const stored = await redis.get(otpKey);

    if (!stored) {
      return res.status(400).json({
        error: "Code expired or not found. Request a new code."
      });
    }

    /*
      Upstash can return the stored value as either
      a string or an already-parsed object depending
      on how it was stored.
    */
    let otpData;

    if (typeof stored === "string") {
      try {
        otpData = JSON.parse(stored);
      } catch {
        return res.status(500).json({
          error: "Invalid OTP data."
        });
      }
    } else {
      otpData = stored;
    }

    if (!otpData || !otpData.hash) {
      return res.status(400).json({
        error: "Code expired or not found. Request a new code."
      });
    }

    const attempts = Number(otpData.attempts || 0);

    if (attempts >= 5) {
      await redis.del(otpKey);

      return res.status(429).json({
        error: "Too many incorrect attempts. Request a new code."
      });
    }

    const suppliedHash = hashOtp(cleanEmail, cleanCode);
    const storedHash = String(otpData.hash);

    const suppliedBuffer = Buffer.from(suppliedHash, "hex");
    const storedBuffer = Buffer.from(storedHash, "hex");

    if (
      suppliedBuffer.length !== storedBuffer.length ||
      !crypto.timingSafeEqual(suppliedBuffer, storedBuffer)
    ) {
      await redis.set(
        otpKey,
        JSON.stringify({
          hash: storedHash,
          attempts: attempts + 1
        }),
        {
          ex: 600
        }
      );

      return res.status(400).json({
        error: "Incorrect verification code."
      });
    }

    // Correct OTP — delete it so it cannot be reused.
    await redis.del(otpKey);

    return res.status(200).json({
      verified: true,
      message: "Email verified successfully."
    });

  } catch (error) {
    console.error("Verify OTP error:", error);

    return res.status(500).json({
      error: "Unable to verify OTP right now."
    });
  }
};
