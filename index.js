const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient, ObjectId } = require("mongodb");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const AppVerify = require("./lib/AppVerify");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("respite");
    const userCollection = db.collection("users");
    const supplyCollection = db.collection("supplies");
    const donationCollection = db.collection("donations");
    const postCollection = db.collection("posts");

    // User Registration
    app.post("/api/v1/register", async (req, res) => {
      const { name, email, password } = req.body;

      // Check if email already exists
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "User already exists",
        });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user into the database
      await userCollection.insertOne({ name, email, password: hashedPassword });

      res.status(201).json({
        success: true,
        message: "User registered successfully. Please login again",
      });
    });

    // User Login
    app.post("/api/v1/login", async (req, res) => {
      const { email, password } = req.body;

      // Find user by email
      const user = await userCollection.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      // Compare hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      // Generate JWT token
      const token = jwt.sign(
        { email: user.email, name: user.name },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.EXPIRES_IN,
        }
      );

      res.json({
        success: true,
        message: "Login successful",
        token,
      });
    });

    app.post("/api/v1/login/oauth", async (req, res) => {
      try {
        const { email, name } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
          await userCollection.insertOne({ name, email });
        }
        const token = jwt.sign({ name, email }, process.env.JWT_SECRET, {
          expiresIn: process.env.EXPIRES_IN,
        });
        res.json({
          success: true,
          message: "Login successful",
          token,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    // ==============================================================
    // Other logic
    // ==============================================================
    app.post("/api/v1/supplies", AppVerify, async (req, res) => {
      try {
        const result = await supplyCollection.insertOne(req.body);
        res.status(200).json({
          success: true,
          message: "supply created successfully",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.get("/api/v1/supplies", async (req, res) => {
      try {
        const category = req.query.category;
        const query = category ? { category } : {};
        const cursor = supplyCollection.find(query);
        const result = await cursor.toArray();
        res.status(200).json({
          success: true,
          message: "supplies retrieved successfully",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.get("/api/v1/supplies/:id", AppVerify, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const supply = await supplyCollection.findOne(query);
        res.status(200).json({
          success: true,
          message: "supply retrieved successfully",
          data: supply,
        });
      } catch (error) {
        console.log(error);
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.delete("/api/v1/supplies/:id", AppVerify, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await supplyCollection.deleteOne(query);
        console.log(result);
        return res.status(200).json({
          success: true,
          message: "supply successfully deleted",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error: error.message,
        });
      }
    });

    app.patch("/api/v1/supplies/:id", AppVerify, async (req, res) => {
      try {
        const id = req.params.id;
        const fillter = { _id: new ObjectId(id) };
        const options = { upsert: true };
        const updateDoc = { $set: req.body };
        const result = await supplyCollection.updateOne(
          fillter,
          updateDoc,
          options
        );
        return res.status(200).json({
          success: true,
          message: "supply successfully updated",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error: error.message,
        });
      }
    });

    app.post("/api/v1/donations", AppVerify, async (req, res) => {
      try {
        const result = await donationCollection.insertOne(req.body);
        res.status(200).json({
          success: true,
          message: "Thanks for your donation",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.get("/api/v1/donations/statics", AppVerify, async (req, res) => {
      try {
        const totalDonations = await donationCollection.countDocuments();
        const cursor = donationCollection.aggregate([
          { $group: { _id: "$category", total: { $sum: 1 } } },
          {
            $project: {
              _id: 1,
              total: 1,
              percentage: {
                $multiply: [{ $divide: ["$total", totalDonations] }, 100],
              },
            },
          },
        ]);
        const data = await cursor.toArray();
        res.status(200).json({
          success: true,
          message: "donation static retrieved successfully",
          data: data,
        });
      } catch (error) {
        console.log(error);
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.get("/api/v1/donations/leaderboard", async (req, res) => {
      try {
        const cursor = donationCollection.aggregate([
          {
            $group: {
              _id: "$userEmail",
              totalDonations: { $sum: "$amount" },
              highestDonation: { $max: "$amount" },
              name: { $first: "$name" },
            },
          },
          {
            $project: {
              userEmail: "$_id",
              totalDonations: 1,
              highestDonation: 1,
              name: 1,
            },
          },
          {
            $sort: { totalDonations: -1 },
          },
        ]);
        const data = await cursor.toArray();
        res.status(200).json({
          success: true,
          message: "donation static retrieved successfully",
          data: data,
        });
      } catch (error) {
        console.log(error);
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.post("/api/v1/posts", AppVerify, async (req, res) => {
      try {
        const result = await postCollection.insertOne(req.body);
        res.status(200).json({
          success: true,
          message: "Successfully posted!",
          data: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    app.get("/api/v1/posts", async (req, res) => {
      try {
        const cursor = await postCollection.find({}).sort({ date: -1 });
        const result = await cursor.toArray();
        res.status(200).json({
          success: true,
          message: "Successfully Reverted posts",
          posts: result,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "something went worng!",
          error,
        });
      }
    });

    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } finally {
  }
}

run().catch(console.dir);

// Test route
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running smoothly",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});
