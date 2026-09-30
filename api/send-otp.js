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

    // -----------------------------------------
    // Validate user information
    // -----------------------------------------

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

    // -----------------------------------------
    // 30-second resend protection
    // -----------------------------------------

    const cooldownKey = `otp:cooldown:${cleanEmail}`;

    const cooldownExists = await redis.get(cooldownKey);

    if (cooldownExists) {
      return res.status(429).json({
        error: "Please wait 30 seconds before requesting another OTP."
      });
    }

    // -----------------------------------------
    // Generate secure 6-digit OTP
    // -----------------------------------------

    const code = String(
      crypto.randomInt(100000, 1000000)
    );

    // -----------------------------------------
    // Store only hashed OTP
    // -----------------------------------------

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

    // -----------------------------------------
    // Safe customer name for HTML
    // -----------------------------------------

    const customerName = escapeHtml(cleanName);

    // -----------------------------------------
    // Professional ZenStay email
    // -----------------------------------------

    const emailHtml = `
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >

  <meta
    name="color-scheme"
    content="light"
  >

  <title>Verify your ZenStay email</title>
</head>

<body
  style="
    margin:0;
    padding:0;
    background:#f5f2ec;
    font-family:
      Arial,
      Helvetica,
      sans-serif;
    color:#11100e;
  "
>

  <!-- Main wrapper -->

  <table
    width="100%"
    cellpadding="0"
    cellspacing="0"
    border="0"
    style="
      background:#f5f2ec;
      padding:40px 16px;
    "
  >

    <tr>

      <td align="center">

        <!-- Email container -->

        <table
          width="100%"
          cellpadding="0"
          cellspacing="0"
          border="0"
          style="
            max-width:580px;
            background:#ffffff;
            border:1px solid #e8e3da;
            border-radius:20px;
            overflow:hidden;
          "
        >

          <!-- Header -->

          <tr>

            <td
              style="
                padding:30px 34px;
                background:#11100e;
              "
            >

              <div
                style="
                  font-size:25px;
                  line-height:1;
                  font-weight:700;
                  letter-spacing:-0.5px;
                  color:#ffffff;
                "
              >
                ZenStay
              </div>

              <div
                style="
                  margin-top:8px;
                  font-size:12px;
                  line-height:18px;
                  letter-spacing:1.2px;
                  text-transform:uppercase;
                  color:#cfcac1;
                "
              >
                Stay better. Live comfortably.
              </div>

            </td>

          </tr>


          <!-- Main content -->

          <tr>

            <td
              style="
                padding:40px 34px 34px 34px;
              "
            >

              <!-- Small label -->

              <div
                style="
                  font-size:11px;
                  line-height:18px;
                  font-weight:700;
                  letter-spacing:1.5px;
                  text-transform:uppercase;
                  color:#a87918;
                  margin-bottom:12px;
                "
              >
                Email verification
              </div>


              <!-- Heading -->

              <div
                style="
                  font-size:30px;
                  line-height:38px;
                  font-weight:700;
                  letter-spacing:-0.7px;
                  color:#11100e;
                  margin-bottom:18px;
                "
              >
                Verify your email
              </div>


              <!-- Greeting -->

              <div
                style="
                  font-size:16px;
                  line-height:26px;
                  color:#34312c;
                "
              >
                Hello ${customerName},
              </div>


              <!-- Explanation -->

              <div
                style="
                  margin-top:10px;
                  font-size:15px;
                  line-height:25px;
                  color:#68645d;
                "
              >
                Use the verification code below to securely
                continue with your ZenStay account.
              </div>


              <!-- OTP box -->

              <table
                width="100%"
                cellpadding="0"
                cellspacing="0"
                border="0"
                style="
                  margin-top:30px;
                  margin-bottom:28px;
                "
              >

                <tr>

                  <td
                    align="center"
                    style="
                      background:#faf8f5;
                      border:1px solid #e8e3da;
                      border-radius:16px;
                      padding:26px 20px;
                    "
                  >

                    <div
                      style="
                        font-size:11px;
                        line-height:18px;
                        font-weight:700;
                        letter-spacing:1.4px;
                        text-transform:uppercase;
                        color:#817b72;
                        margin-bottom:12px;
                      "
                    >
                      Your verification code
                    </div>

                    <div
                      style="
                        font-size:36px;
                        line-height:44px;
                        font-weight:700;
                        letter-spacing:8px;
                        color:#11100e;
                        padding-left:8px;
                      "
                    >
                      ${code}
                    </div>

                  </td>

                </tr>

              </table>


              <!-- Expiration -->

              <div
                style="
                  font-size:14px;
                  line-height:22px;
                  color:#68645d;
                "
              >
                This code is valid for
                <strong style="color:#34312c;">
                  10 minutes
                </strong>.
              </div>


              <!-- Security message -->

              <div
                style="
                  margin-top:24px;
                  padding:16px 18px;
                  background:#f8f6f2;
                  border-left:3px solid #d49a2a;
                  border-radius:8px;
                "
              >

                <div
                  style="
                    font-size:13px;
                    line-height:21px;
                    color:#5f5a52;
                  "
                >
                  If you didn't request this verification code,
                  you can safely ignore this email.
                  Never share your verification code with anyone.
                </div>

              </div>

            </td>

          </tr>


          <!-- Footer -->

          <tr>

            <td
              style="
                padding:24px 34px 28px 34px;
                border-top:1px solid #eeeae3;
                background:#fcfbf9;
              "
            >

              <div
                style="
                  font-size:13px;
                  line-height:20px;
                  font-weight:700;
                  color:#34312c;
                "
              >
                ZenStay
              </div>

              <div
                style="
                  margin-top:5px;
                  font-size:12px;
                  line-height:19px;
                  color:#8a847b;
                "
              >
                Your space. Your comfort. Your stay.
              </div>

              <div
                style="
                  margin-top:16px;
                  font-size:11px;
                  line-height:18px;
                  color:#aaa49b;
                "
              >
                This is an automated security email.
                Please do not reply to this message.
              </div>

            </td>

          </tr>

        </table>

      </td>

    </tr>

  </table>

</body>

</html>
`;

    // -----------------------------------------
    // Plain-text version
    // -----------------------------------------

    const emailText = `
ZENSTAY
Stay better. Live comfortably.

EMAIL VERIFICATION

Hello ${cleanName},

Use the verification code below to securely continue with your ZenStay account.

Your verification code:

${code}

This code is valid for 10 minutes.

If you didn't request this verification code, you can safely ignore this email.

Never share your verification code with anyone.

ZenStay
Your space. Your comfort. Your stay.

This is an automated security email.
Please do not reply to this message.
`;

    // -----------------------------------------
    // Send email through Sendlib
    // -----------------------------------------

    const sendResponse = await fetch(
      "https://sendlib.samueltuoyo.com/api/send",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${process.env.SENDLIB_API_KEY}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from: process.env.OTP_FROM_EMAIL,

          to: cleanEmail,

          subject:
            "Your ZenStay verification code",

          html:
            emailHtml,

          text:
            emailText
        })
      }
    );

    const sendData =
      await sendResponse
        .json()
        .catch(() => ({}));


    // -----------------------------------------
    // Handle Sendlib failure
    // -----------------------------------------

    if (!sendResponse.ok) {

      console.error(
        "Sendlib error:",
        sendData
      );

      // Remove the OTP if delivery failed.
      await redis.del(otpKey);

      return res.status(502).json({
        error:
          "Email delivery failed. Please try again."
      });
    }


    // -----------------------------------------
    // Success
    // -----------------------------------------

    return res.status(200).json({

      success: true,

      message:
        "OTP sent successfully."

    });

  } catch (error) {

    console.error(
      "Send OTP error:",
      error
    );

    return res.status(500).json({

      error:
        "Unable to send OTP right now."

    });

  }
};
