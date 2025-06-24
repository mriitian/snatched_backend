import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";
import bcrypt from "bcryptjs"; // ✅ Add this
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const DB_URI = process.env.DB_URI;
let db;

// CORS config
app.use(
  cors({
    origin: "http://localhost:8080", // ✅ exact origin
    credentials: true, // ✅ required for cookies/sessions
  })
);
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

MongoClient.connect(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then((client) => {
    console.log("✅ Connected to MongoDB");
    db = client.db("testDB");

    // Passport setup
    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((user, done) => done(null, user));
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: "/auth/google/callback",
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            const users = db.collection("users");
            const existingUser = await users.findOne({ googleId: profile.id });

            if (existingUser) return done(null, existingUser);

            const newUser = {
              fullName: profile.displayName,
              email: profile.emails[0].value,
              googleId: profile.id,
              picture: profile.photos[0].value,
            };

            await users.insertOne(newUser);
            done(null, newUser);
          } catch (err) {
            done(err, null);
          }
        }
      )
    );
  })
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "http://localhost:8080/",
    failureRedirect: "http://localhost:8080/login",
  })
);

app.get("/auth/user", (req, res) => {
  if (req.user) {
    res.status(200).json(req.user);
  } else {
    res.status(200).json(null); // ✅ always respond with valid JSON
  }
});
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.status(200).json({ message: "Logged out successfully" }); // ✅ send JSON
    });
  });
});

// Register route
app.post("/register", async (req, res) => {
  const { fullName, email, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const users = db.collection("users");

    const userExists = await users.findOne({ email });
    if (userExists) {
      return res.status(409).json({ error: "Email already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await users.insertOne({
      fullName,
      email,
      password: hashedPassword,
    });

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("❌ Registration error:", error);
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const users = db.collection("users");

    const user = await users.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    // Optional: Generate JWT token
    const token = jwt.sign({ id: user._id }, "secretKey", { expiresIn: "1h" });

    res.status(200).json({
      message: "Login successful.",
      token, // You can store this in client for protected routes
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/users", async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ error: "Database not connected" });
    }

    const users = await db
      .collection("users")
      .find({}, { projection: { password: 0 } })
      .toArray(); // exclude passwords
    res.status(200).json(users);
  } catch (err) {
    console.error("❌ Error fetching users:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send("✅ Backend is running. Go to /test-db to test MongoDB.");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
