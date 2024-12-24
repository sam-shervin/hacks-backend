import prisma from "./db/prismaInstance.js";
import express from "express";
import bcrypt from "bcrypt";
import {
  generateSessionToken,
  createSession,
  validateSessionToken,
  invalidateSession,
  setSessionTokenCookie,
  deleteSessionTokenCookie,
} from "./auth/session.js";
import nodemailer from "nodemailer";
import rateLimit from "express-rate-limit";

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.NODEMAILER_MAIL,
    pass: process.env.NODEMAILER_PASS,
  },
});

const app = express();
const port = 8032;

// Define the rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply the rate limiter to all requests
app.use(limiter);

app.use(express.json());

// CORS setup
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// Signup endpoint
import crypto from "crypto";

// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a unique verification token
    const verifyToken = crypto.randomBytes(32).toString("hex");

    // Set the expiration time (12 hours from now)
    const expireAt = new Date(Date.now() + 12 * 60 * 60 * 1000); // 12 hours

    // Save user with the verification token and expiration time
    await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        verifyToken,
        verifyTokenExpireAt: expireAt, // Store expiration time
      },
    });

    // Send verification email
    const verifyLink = `${
      process.env.NODE_ENV === "development"
        ? process.env.DEV_DOMAIN
        : process.env.PROD_DOMAIN
    }/verify?token=${verifyToken}`;
    await transporter.sendMail({
      from: '"STEAM" <wateryousayin24@gmail.com>',
      to: email,
      subject: "Verify Your Email",
      html: `<p>Click <a href="${verifyLink}">here</a> to verify your email and continue using the website.</p>
      <p>This link will expire in 12 hours.</p>
      <p>If you didn't request this email, you can safely ignore it.</p>`,
    });

    res.status(201).json({
      message:
        "Signup successful. Please check your email to verify your account.",
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify endpoint
app.get("/verify", async (req, res) => {
  try {
    const { token } = req.query;

    // Find the user with the provided token
    const user = await prisma.user.findFirst({
      where: { verifyToken: token },
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Invalid or expired verification token" });
    }

    // Check if the token has expired
    const currentTime = new Date();
    if (currentTime > new Date(user.verifyTokenExpireAt)) {
      return res.status(400).json({ error: "Verification token has expired" });
    }

    // Update the user's `verified` field to true and clear the `verifyToken`
    await prisma.user.update({
      where: { id: user.id },
      data: {
        verified: true,
        verifyToken: null, // Clear the verification token
        verifyTokenExpireAt: null, // Clear the expiration time
      },
    });

    res.redirect(
      `${
        process.env.NODE_ENV === "development"
          ? process.env.FRONTEND_DEV_URL
          : process.env.FRONTEND_PROD_URL
      }/login`
    ); // Redirect to the login page
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    if (!user.verified) {
      return res
        .status(400)
        .json({ error: "Email not verified. Please check your inbox." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Generate session token and create session
    const sessionToken = generateSessionToken();
    await createSession(sessionToken, user.id);

    // Set session token in the cookie
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7); // 7 days
    setSessionTokenCookie(res, sessionToken, expiresAt);

    res.status(200).json({ message: "Login successful" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected route example
app.get("/profile", async (req, res) => {
  try {
    const cookies = req.headers.cookie || "";
    const sessionToken = cookies
      .split(";")
      .find((cookie) => cookie.trim().startsWith("session="))
      ?.split("=")[1];

    if (!sessionToken) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { session, user } = await validateSessionToken(sessionToken);
    if (!session) {
      return res.status(401).json({ error: "Session invalid" });
    }

    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logout endpoint
app.post("/logout", async (req, res) => {
  try {
    const cookies = req.headers.cookie || "";
    const sessionToken = cookies
      .split(";")
      .find((cookie) => cookie.trim().startsWith("session="))
      ?.split("=")[1];

    if (sessionToken) {
      const { session } = await validateSessionToken(sessionToken);
      if (session) {
        await invalidateSession(session.id);
      }
    }

    // Delete session token cookie
    deleteSessionTokenCookie(res);

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test endpoint to verify everything is working
app.get("/test", (req, res) => {
  res.send("Hello World");
});


app.use((err, req, res, next) => {
  console.error(err.stack); // Logs the error stack for debugging
  res.status(500).json({ error: "Internal Server Error" }); // Send a generic error message
});


// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
