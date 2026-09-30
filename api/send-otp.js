const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const redis = Redis.fromEnv();

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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
    const { name, email } = req.body || {};

    const cleanName = String(name || "").trim();
    const cleanEmail = normalizeEmail(email);

    if (!cleanName) {
      return res.status(400).json({
        error: "Please enter your name."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    // Prevent requesting a new OTP too frequently.
    const cooldownKey = `otp:cooldown:${cleanEmail}`;

    const cooldownExists = await redis.get(cooldownKey);

    if (cooldownExists) {
      return res.status(429).json({
        error: "Please wait 30 seconds before requesting another OTP."
      });
    }

    // Generate a 6-digit OTP.
    const code = String(crypto.randomInt(100000, 1000000));

    // Store only the HMAC hash, never the OTP itself.
    const otpHash = hashOtp(cleanEmail, code);

    const otpKey = `otp:${cleanEmail}`;

    await redis.set(
      otpKey,
      JSON.stringify({
        hash: otpHash,
        attempts: 0
      }),
      {
        ex: 600
      }
    );

    await redis.set(
      cooldownKey,
      "1",
      {
        ex: 30
      }
    );

    const customerName = escapeHtml(cleanName);

    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your ZenStay verification code</title>
</head>

<body style="
  margin:0;
  padding:0;
  background:#f7f4ee;
  font-family:Arial,Helvetica,sans-serif;
  color:#11100e;
">

  <div style="
    max-width:600px;
    margin:40px auto;
    background:#ffffff;
    border:1px solid #ebe7df;
    border-radius:18px;
    overflow:hidden;
  ">

    <div style="
      padding:28px;
      background:#11100e;
      color:#ffffff;
    ">
      <h1 style="
        margin:0;
        font-size:24px;
      ">
        ZenStay
      </h1>
    </div>

    <div style="padding:32px;">

      <p style="font-size:16px;">
        Hello ${customerName},
      </p>

      <p style="font-size:16px;line-height:1.6;">
        Use the verification code below to continue signing in to ZenStay.
      </p>

      <div style="
        margin:28px 0;
        padding:22px;
        text-align:center;
        background:#f7f4ee;
        border-radius:14px;
      ">

        <div style="
          font-size:36px;
          font-weight:700;
          letter-spacing:8px;
        ">
          ${code}
        </div>

      </div>

      <p style="
        font-size:14px;
        color:#68645d;
        line-height:1.6;
      ">
        This code expires in 10 minutes.
        If you did not request this code, you can safely ignore this email.
      </p>

    </div>

  </div>

</body>
</html>
`;

    const emailText = `
Hello ${cleanName},

Your ZenStay verification code is:

${code}

This code expires in 10 minutes.

If you did not request this code, you can safely ignore this email.
`;

    // Send through Sendlib using the connected Gmail account.
    const sendResponse = await fetch(
      "https://sendlib.samueltuoyo.com/api/send",
      {
        method: "POST",

        headers: {
          "Authorization": `Bearer ${process.env.SENDLIB_API_KEY}`,
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          from: process.env.OTP_FROM_EMAIL,
          to: cleanEmail,
          subject: "Your ZenStay verification code",
          html: emailHtml,
          text: emailText
        })
      }
    );

    const sendData = await sendResponse.json().catch(() => ({}));

    if (!sendResponse.ok) {
      console.error("Sendlib error:", sendData);

      // Remove OTP because the email was not successfully sent.
      await redis.del(otpKey);

      return res.status(502).json({
        error: "Email delivery failed. Please try again."
      });
    }

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully."
    });

  } catch (error) {
    console.error("Send OTP error:", error);

    return res.status(500).json({
      error: "Unable to send OTP right now."
    });
  }
};
