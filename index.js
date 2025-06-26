import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
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

              // 🆕 Add default fields for consistency
              joinDate: new Date().toLocaleString("default", {
                month: "short",
                year: "numeric",
              }),
              rewardPoints: 0,
              membershipLevel: "Bronze",
              phone: "",
              address: "",
              city: "",
              state: "",
              zip: "",
              country: "",
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

// app.use((req, res, next) => {
//   console.log(`🌐 Incoming request: ${req.method} ${req.path}`);
//   next();
// });

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

    const newUser = {
      fullName,
      email,
      password: hashedPassword,
      joinDate: new Date().toLocaleString("default", {
        month: "short",
        year: "numeric",
      }),
      rewardPoints: 0,
      membershipLevel: "Bronze",
      phone: "",
      address: "",
      city: "",
      state: "",
      zip: "",
      country: "",
    };

    await users.insertOne(newUser);

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
    const token = jwt.sign(
      { id: user._id.toString() },
      process.env.JWT_SECRET,
      {
        expiresIn: "2h",
      }
    );

    res.status(200).json({
      message: "Login successful.",
      token,
      email: user.email,
      fullName: user.fullName,
      joinDate: user.joinDate,
      rewardPoints: user.rewardPoints,
      membershipLevel: user.membershipLevel,
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

app.get("/user/profile", async (req, res) => {
  console.log("🔥 /user/profile entered");
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID in token." });
    }

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(userId) }, { projection: { password: 0 } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (err) {
    console.error("❌ /user/profile error:", err);
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

app.get("/user/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const user = await db
      .collection("users")
      .findOne({ email }, { projection: { password: 0 } });
    if (!user) return res.status(404).json({ error: "User not found." });
    res.json(user);
  } catch (error) {
    console.error("❌ Fetch user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/user/:email", async (req, res) => {
  console.log("Called user/:email");
  const { email } = req.params;
  const updateData = { ...req.body };

  // Remove _id if it exists in payload
  if ("_id" in updateData) delete updateData._id;

  try {
    const users = db.collection("users");

    const result = await users.updateOne({ email }, { $set: updateData });

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.status(200).json({ message: "User updated successfully." });
  } catch (error) {
    console.error("❌ Update user error:", error);
    res.status(500).json({ error: "Failed to update user." });
  }
});

app.post("/orders", async (req, res) => {
  const order = req.body;

  if (!order?.userEmail || !Array.isArray(order.items)) {
    return res.status(400).json({ error: "Invalid order format." });
  }

  try {
    order.createdAt = new Date();
    const result = await db.collection("orders").insertOne(order);
    res.status(201).json({
      message: "Order placed successfully",
      orderId: result.insertedId,
    });
  } catch (err) {
    console.error("❌ Create order error:", err);
    res.status(500).json({ error: "Failed to place order." });
  }
});

app.get("/orders/:email", async (req, res) => {
  const email = req.params.email;

  try {
    const orders = await db
      .collection("orders")
      .find({ userEmail: email })
      .toArray();
    res.status(200).json(orders);
  } catch (err) {
    console.error("❌ Fetch orders error:", err);
    res.status(500).json({ error: "Failed to fetch orders." });
  }
});

app.get("/orders/:email/:status", async (req, res) => {
  const { email, status } = req.params;

  try {
    const orders = await db
      .collection("orders")
      .find({ userEmail: email, status })
      .toArray();
    res.status(200).json(orders);
  } catch (err) {
    console.error("❌ Filtered order fetch error:", err);
    res.status(500).json({ error: "Failed to fetch filtered orders." });
  }
});

// Get all product listings
app.get("/products", async (req, res) => {
  try {
    const products = await db.collection("products").find().toArray();
    res.status(200).json(products);
  } catch (err) {
    console.error("❌ Error fetching products:", err);
    res.status(500).json({ error: "Failed to fetch products." });
  }
});

// Get detailed product info by ID
app.get("/details/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const detail = await db.collection("details").findOne({ id });
    if (!detail) {
      return res.status(404).json({ error: "Product detail not found." });
    }

    res.status(200).json(detail);
  } catch (err) {
    console.error("❌ Error fetching product detail:", err);
    res.status(500).json({ error: "Failed to fetch product detail." });
  }
});

// auction products
app.get("/auctions", async (req, res) => {
  try {
    const auctions = await db.collection("auctions").find().toArray();
    res.status(200).json(auctions);
  } catch (err) {
    console.error("❌ Error fetching products:", err);
    res.status(500).json({ error: "Failed to fetch products." });
  }
});

app.get("/", (req, res) => {
  res.send("✅ Backend is running. Go to /test-db to test MongoDB.");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
