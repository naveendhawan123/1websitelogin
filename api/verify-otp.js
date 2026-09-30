const { Redis } = require("@upstash/redis");
const crypto = require("crypto");

const redis = Redis.fromEnv();


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

    const email =
      String(
        (req.body || {}).email || ""
      )
      .trim()
      .toLowerCase();


    const code =
      String(
        (req.body || {}).code || ""
      )
      .trim();


    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email)
      ||
      !/^\d{6}$/.test(code)
    ) {

      return res
        .status(400)
        .json({
          error:
            "Enter a valid email and six-digit code."
        });

    }


    if (
      !process.env.OTP_HMAC_SECRET ||
      !process.env.UPSTASH_REDIS_REST_URL ||
      !process.env.UPSTASH_REDIS_REST_TOKEN
    ) {

      return res
        .status(500)
        .json({
          error:
            "OTP verification is not configured in Vercel."
        });

    }



    // ==============================
    // FIND STORED OTP
    // ==============================

    const key =
      "otp-code:" +
      crypto
        .createHash("sha256")
        .update(email)
        .digest("hex");


    const stored =
      await redis.get(key);


    if (!stored) {

      return res
        .status(400)
        .json({
          error:
            "Code expired or not found. Request a new code."
        });

    }


    const record =
      typeof stored === "string"
        ? JSON.parse(stored)
        : stored;



    // ==============================
    // MAXIMUM 5 ATTEMPTS
    // ==============================

    if (
      (record.attempts || 0) >= 5
    ) {

      await redis.del(key);


      return res
        .status(429)
        .json({
          error:
            "Too many incorrect attempts. Request a new code."
        });

    }



    // ==============================
    // COMPARE OTP SECURELY
    // ==============================

    const expected =
      Buffer.from(
        record.hash,
        "hex"
      );


    const actual =
      Buffer.from(
        hashCode(
          email,
          code
        ),
        "hex"
      );


    const matches =
      expected.length === actual.length &&
      crypto.timingSafeEqual(
        expected,
        actual
      );


    if (!matches) {

      record.attempts =
        (record.attempts || 0) + 1;


      const ttl =
        await redis.ttl(key);


      if (ttl > 0) {

        await redis.set(
          key,
          JSON.stringify(record),
          {
            ex: ttl
          }
        );

      }


      return res
        .status(400)
        .json({
          error:
            "Incorrect code. Please try again."
        });

    }



    // ==============================
    // SUCCESS
    // ==============================

    await redis.del(key);


    return res
      .status(200)
      .json({
        ok: true,
        verified: true
      });


  } catch (error) {

    console.error(
      "verify-otp error:",
      error
    );


    return res
      .status(500)
      .json({
        error:
          "Could not verify the code. Please try again."
      });

  }

};
