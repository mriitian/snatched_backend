import express from "express";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const DB_URI = process.env.DB_URI;

app.use(express.json());
let db;

// Connect to MongoDB
MongoClient.connect(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then((client) => {
    console.log("✅ Connected to MongoDB");
    db = client.db("testDB"); // Create or use 'testDB'
  })
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Test route to insert & retrieve a document
app.get("/test-db", async (req, res) => {
  try {
    const collection = db.collection("testCollection");

    const existing = await collection.findOne({ name: "Vedant" });

    if (!existing) {
      await collection.insertOne({
        name: "Vedant",
        message: "MongoDB is working!",
      });
      console.log("📝 Document inserted");
    } else {
      console.log("⚠️ Document already exists, not inserting again");
    }

    const data = await collection.find({}).toArray();
    res.status(200).json(data);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error connecting to DB");
  }
});

app.get("/", (req, res) => {
  res.send("✅ Backend is running. Go to /test-db to test MongoDB.");
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
