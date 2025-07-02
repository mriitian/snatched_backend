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
// ✅ Multiple allowed origins
const allowedOrigins = [
  "http://localhost:8080",
  "https://snatched-brown.vercel.app",
];

var currentOrigin = "";
// ✅ Dynamic CORS config
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // Allow curl or mobile apps
      currentOrigin = origin;
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
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
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(`${currentOrigin || "http://localhost:8080"}`);
  }
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
      { id: user._id.toString(), email: user.email },
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

app.get("/search", async (req, res) => {
  const q = req.query.q?.toString().toLowerCase() || "";

  try {
    // Fetch the single document
    const allCategoriesDoc = await db.collection("products").findOne({});

    if (!allCategoriesDoc) {
      return res.json([]);
    }

    let allProducts = [];

    // Loop all category arrays
    for (const [category, products] of Object.entries(allCategoriesDoc)) {
      if (Array.isArray(products)) {
        allProducts.push(
          ...products.map((p) => ({
            ...p,
            category,
          }))
        );
      }
    }

    // Filter products matching the search query
    const matchingProducts = allProducts.filter((p) =>
      p.name?.toLowerCase().includes(q)
    );

    res.json(matchingProducts);
  } catch (err) {
    console.error("❌ Search error:", err);
    res.status(500).json({ error: "Search failed." });
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

app.post("/cart", async (req, res) => {
  let userEmail;

  // Check Google OAuth user
  if (req.user && req.user.email) {
    userEmail = req.user.email;
  } else {
    // Check JWT token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.id;

      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(userId) });

      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }
      userEmail = user.email;
    } catch (err) {
      console.error("❌ Add to cart error:", err);
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  }

  const { productId, quantity, selectedColor } = req.body;

  if (!productId || !quantity) {
    return res
      .status(400)
      .json({ error: "Product ID and quantity are required." });
  }

  try {
    const cartCollection = db.collection("cart");

    let cartDoc = await cartCollection.findOne({ userEmail });

    if (!cartDoc) {
      await cartCollection.insertOne({
        userEmail,
        items: [
          {
            productId,
            quantity,
            selectedColor,
          },
        ],
      });
    } else {
      const existingIndex = cartDoc.items.findIndex(
        (item) =>
          item.productId === productId && item.selectedColor === selectedColor
      );

      if (existingIndex !== -1) {
        cartDoc.items[existingIndex].quantity += quantity;
      } else {
        cartDoc.items.push({
          productId,
          quantity,
          selectedColor,
        });
      }

      await cartCollection.updateOne(
        { userEmail },
        { $set: { items: cartDoc.items } }
      );
    }

    res.status(200).json({ message: "Product added to cart!" });
  } catch (err) {
    console.error("❌ Add to cart error:", err);
    res.status(500).json({ error: "Failed to add to cart." });
  }
});

app.get("/cart", async (req, res) => {
  try {
    let userEmail = null;

    if (req.user && req.user.email) {
      userEmail = req.user.email;
    } else {
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // ✅ fetch user by id
        const user = await db
          .collection("users")
          .findOne({ _id: new ObjectId(decoded.id) });

        if (user) {
          userEmail = user.email;
        }
      }
    }

    if (!userEmail) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const cart = await db.collection("cart").findOne({ userEmail });

    if (!cart) {
      return res.status(200).json({ userEmail, items: [] });
    }

    res.status(200).json(cart);
  } catch (err) {
    console.error("❌ Error fetching cart:", err);
    res.status(500).json({ error: "Failed to fetch cart." });
  }
});

// PATCH /cart
app.patch("/cart", async (req, res) => {
  const { productId, selectedColor, quantity } = req.body;
  console.log(req.body);
  let userEmail = null;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(decoded.id) });
    userEmail = user?.email;
  }

  if (!userEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // Update the quantity of the specific item
  const result = await db.collection("cart").updateOne(
    {
      userEmail,
      "items.productId": productId,
      "items.selectedColor": selectedColor,
    },
    {
      $set: {
        "items.$.quantity": quantity,
      },
    }
  );

  res.status(200).json({ message: "Quantity updated" });
});

// DELETE /cart/item
app.delete("/cart/item", async (req, res) => {
  const { productId, selectedColor } = req.body;
  let userEmail = null;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(decoded.id) });
    userEmail = user?.email;
  }

  if (!userEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const result = await db.collection("cart").updateOne(
    { userEmail },
    {
      $pull: {
        items: {
          productId,
          selectedColor,
        },
      },
    }
  );

  res.status(200).json({ message: "Item removed" });
});

app.delete("/cart", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let userEmail = null;

    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(decoded.id) });

      if (user) {
        userEmail = user.email;
      }
    }

    if (!userEmail) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const result = await db
      .collection("cart")
      .updateOne({ userEmail }, { $set: { items: [] } });

    return res.status(200).json({ message: "Cart cleared successfully" });
  } catch (err) {
    console.error("❌ Error clearing cart:", err);
    res.status(500).json({ error: "Failed to clear cart" });
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

app.post("/wishlist", async (req, res) => {
  let userEmail;

  // Check for Google OAuth user
  if (req.user && req.user.email) {
    userEmail = req.user.email;
  } else {
    // Check for JWT token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.id;

      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(userId) });

      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }
      userEmail = user.email;
    } catch (err) {
      console.error("❌ Wishlist add error:", err);
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  }

  const { productId, selectedColor } = req.body;

  if (!productId) {
    return res.status(400).json({ error: "Product ID is required." });
  }

  try {
    const wishlistCollection = db.collection("wishlist");

    let wishlistDoc = await wishlistCollection.findOne({ userEmail });

    if (!wishlistDoc) {
      await wishlistCollection.insertOne({
        userEmail,
        items: [{ productId, selectedColor }],
      });
    } else {
      const alreadyExists = wishlistDoc.items.some(
        (item) =>
          item.productId === productId && item.selectedColor === selectedColor
      );

      if (!alreadyExists) {
        wishlistDoc.items.push({ productId, selectedColor });

        await wishlistCollection.updateOne(
          { userEmail },
          { $set: { items: wishlistDoc.items } }
        );
      }
    }

    res.status(200).json({ message: "Added to wishlist!" });
  } catch (err) {
    console.error("❌ Wishlist add error:", err);
    res.status(500).json({ error: "Failed to add to wishlist." });
  }
});

app.get("/wishlist", async (req, res) => {
  let userEmail;

  if (req.user && req.user.email) {
    userEmail = req.user.email;
  } else {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.id;

      const user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(userId) });

      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }
      userEmail = user.email;
    } catch (err) {
      console.error("❌ Wishlist fetch error:", err);
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  }

  try {
    const wishlist = await db.collection("wishlist").findOne({ userEmail });

    res.status(200).json(wishlist || { userEmail, items: [] });
  } catch (err) {
    console.error("❌ Wishlist fetch error:", err);
    res.status(500).json({ error: "Failed to fetch wishlist." });
  }
});

app.delete("/wishlist/item", async (req, res) => {
  const { productId, selectedColor } = req.body;
  let userEmail = null;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(decoded.id) });

    userEmail = user?.email;
  }

  if (!userEmail) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Remove the item from the wishlist array
    await db.collection("wishlist").updateOne(
      { userEmail },
      {
        $pull: {
          items: {
            productId,
            selectedColor,
          },
        },
      }
    );

    // Check if the wishlist is now empty
    const updatedDoc = await db.collection("wishlist").findOne({ userEmail });

    if (updatedDoc && updatedDoc.items.length === 0) {
      // Delete the entire wishlist document
      await db.collection("wishlist").deleteOne({ userEmail });
    }

    res.status(200).json({ message: "Item removed from wishlist." });
  } catch (err) {
    console.error("❌ Wishlist remove error:", err);
    res.status(500).json({ error: "Failed to remove item from wishlist." });
  }
});

app.get("/", (req, res) => {
  res.send("✅ Backend is running. Go to /test-db to test MongoDB.");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
