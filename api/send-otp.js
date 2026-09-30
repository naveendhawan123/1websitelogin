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

// Simple, light, text-first email (this is what inbox providers trust).
// No dark banners, no slogans, no images, no marketing language.
function buildEmail({ name, email, code }) {
  const safeName = escapeHtml(name);
  const safeEmail = escapeHtml(email);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${code} is your ZenStay code</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;font-family:Helvetica,Arial,sans-serif;color:#262626;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
    Your ZenStay confirmation code is ${code}.
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;">
          <tr>
            <td style="padding-bottom:24px;font-size:22px;font-weight:700;color:#11100e;">
              ZenStay
            </td>
          </tr>
          <tr>
            <td style="font-size:16px;line-height:24px;color:#262626;">
              Hi ${safeName},
            </td>
          </tr>
          <tr>
            <td style="padding-top:12px;font-size:16px;line-height:24px;color:#262626;">
              Someone tried to sign in to ZenStay with
              <span style="color:#262626;text-decoration:none;">${safeEmail}</span>.
              If it was you, enter this confirmation code:
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:28px 0;font-size:34px;line-height:40px;font-weight:600;color:#262626;">
              ${code}
            </td>
          </tr>
          <tr>
            <td style="font-size:14px;line-height:22px;color:#6b6b6b;">
              This code expires in 10 minutes. If you didn't request it, you can ignore this email.
            </td>
          </tr>
          <tr>
            <td style="padding-top:32px;font-size:12px;line-height:18px;color:#8e8e8e;border-top:1px solid #efefef;">
              This message was sent to ${safeEmail} by ZenStay.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  // Plain-text twin. Keep it close to the HTML version.
  const text = `Hi ${name},

Someone tried to sign in to ZenStay with ${email}. If it was you, enter this confirmation code:

${code}

This code expires in 10 minutes. If you didn't request it, you can ignore this email.

This message was sent to ${email} by ZenStay.`;

  return { html, text };
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { name, email } = req.body || {};

    const cleanName = String(name || "").trim().slice(0, 60);
    const cleanEmail = normalizeEmail(email);

    if (!cleanName) {
      return res.status(400).json({ error: "Please enter your name." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    // 30-second resend protection
    const cooldownKey = `otp:cooldown:${cleanEmail}`;
    if (await redis.get(cooldownKey)) {
      return res.status(429).json({
        error: "Please wait 30 seconds before requesting another OTP."
      });
    }

    // Secure 6-digit OTP
    const code = String(crypto.randomInt(100000, 1000000));

    // Store only the hashed OTP
    const otpKey = `otp:${cleanEmail}`;
    await redis.set(
      otpKey,
      JSON.stringify({ hash: hashOtp(cleanEmail, code), attempts: 0 }),
      { ex: 600 }
    );
    await redis.set(cooldownKey, "1", { ex: 30 });

    const { html, text } = buildEmail({
      name: cleanName,
      email: cleanEmail,
      code
    });

    const sendResponse = await fetch("https://sendlib.samueltuoyo.com/api/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.SENDLIB_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        // Must look like: ZenStay <no-reply@yourdomain.com>
        from: process.env.OTP_FROM_EMAIL,
        to: cleanEmail,
        // Code in the subject = same pattern Instagram, Google, etc. use
        subject: `${code} is your ZenStay code`,
        html,
        text
      })
    });

    const sendData = await sendResponse.json().catch(() => ({}));

    if (!sendResponse.ok) {
      console.error("Sendlib error:", sendData);
      // Clear both keys so the user can retry immediately
      await redis.del(otpKey);
      await redis.del(cooldownKey);
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
    return res.status(500).json({ error: "Unable to send OTP right now." });
  }
};
