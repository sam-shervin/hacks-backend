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



const app = express();
const port = 8032;

app.use(express.json());

// CORS setup
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

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
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    // Generate session token and create session
    const sessionToken = generateSessionToken();
    await createSession(sessionToken, newUser.id);

    // Set session token in the cookie
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7); // 7 days
    setSessionTokenCookie(res, sessionToken, expiresAt);

    res.status(201).json({ message: "User created successfully" });
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

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
