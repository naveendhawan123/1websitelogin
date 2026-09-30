const { Redis } = require("@upstash/redis");
const { Resend } = require("resend");
const crypto = require("crypto");

const redis = Redis.fromEnv();
const resend = new Resend(process.env.RESEND_API_KEY);


function hashCode(email, code) {

  return crypto
    .createHmac(
      "sha256",
      process.env.OTP_HMAC_SECRET
    )
    .update(
      email.toLowerCase() + ":" + code
    )
    .digest("hex");

}


module.exports = async (req, res) => {

  if (req.method !== "POST") {

    return res
      .status(405)
      .json({
        error: "Method not allowed."
      });

  }


  try {

    const {
      name,
      email
    } = req.body || {};


    const normalizedEmail =
      String(email || "")
        .trim()
        .toLowerCase();


    const cleanName =
      String(name || "")
        .trim()
        .slice(0, 100);


    if (
      !cleanName ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(normalizedEmail)
    ) {

      return res
        .status(400)
        .json({
          error:
            "Enter a valid name and email address."
        });

    }


    if (
      !process.env.RESEND_API_KEY ||
      !process.env.OTP_HMAC_SECRET ||
      !process.env.UPSTASH_REDIS_REST_URL ||
      !process.env.UPSTASH_REDIS_REST_TOKEN ||
      !process.env.OTP_FROM_EMAIL
    ) {

      return res
        .status(500)
        .json({
          error:
            "Email OTP service is not fully configured in Vercel."
        });

    }



    // ==============================
    // RATE LIMIT
    // ==============================

    const rateKey =
      "otp-rate:" +
      crypto
        .createHash("sha256")
        .update(normalizedEmail)
        .digest("hex");


    const allowed =
      await redis.set(
        rateKey,
        "1",
        {
          nx: true,
          ex: 30
        }
      );


    if (!allowed) {

      return res
        .status(429)
        .json({
          error:
            "Please wait 30 seconds before requesting another code."
        });

    }



    // ==============================
    // GENERATE 6-DIGIT OTP
    // ==============================

    const code =
      String(
        crypto.randomInt(
          0,
          1000000
        )
      ).padStart(6, "0");



    // ==============================
    // STORE HASH
    // OTP EXPIRES AFTER 10 MINUTES
    // ==============================

    const codeKey =
      "otp-code:" +
      crypto
        .createHash("sha256")
        .update(normalizedEmail)
        .digest("hex");


    await redis.set(
      codeKey,
      JSON.stringify({
        hash:
          hashCode(
            normalizedEmail,
            code
          ),
        attempts: 0
      }),
      {
        ex: 600
      }
    );



    // ==============================
    // SEND EMAIL
    // ==============================

    const result =
      await resend.emails.send({

        from:
          process.env.OTP_FROM_EMAIL,

        to: [
          normalizedEmail
        ],

        subject:
          "Your ZenStay verification code",

        text:
`Hello ${cleanName},

Your ZenStay verification code is:

${code}

This code expires in 10 minutes.

Do not share this code with anyone.

If you did not request this code, you can ignore this email.

— ZenStay`,

        html:
`
<div style="
  font-family:Arial,sans-serif;
  max-width:520px;
  margin:auto;
  padding:24px;
  color:#111;
">

  <h2>
    ZenStay verification
  </h2>

  <p>
    Hello ${escapeHtml(cleanName)},
  </p>

  <p>
    Your six-digit verification code is:
  </p>

  <div style="
    font-size:32px;
    font-weight:bold;
    letter-spacing:8px;
    padding:16px;
    background:#f7f4ee;
    border-radius:12px;
    text-align:center;
  ">
    ${code}
  </div>

  <p>
    This code expires in 10 minutes.
  </p>

  <p>
    Do not share this code with anyone.
  </p>

  <p>
    If you did not request this code,
    you can ignore this email.
  </p>

  <p>
    — ZenStay
  </p>

</div>
`

      });


    if (result.error) {

      await redis.del(codeKey);


      return res
        .status(502)
        .json({
          error:
            "Email delivery failed. Check your Resend sender settings."
        });

    }


    return res
      .status(200)
      .json({
        ok: true
      });


  } catch (error) {

    console.error(
      "send-otp error:",
      error
    );


    return res
      .status(500)
      .json({
        error:
          "Could not send the verification email. Please try again."
      });

  }

};



function escapeHtml(value) {

  return String(value)
    .replace(
      /[&<>"']/g,
      function (character) {

        const entities = {

          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;"

        };

        return entities[character];

      }
    );

}
