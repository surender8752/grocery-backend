require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("./cron");

const Product = require("./models/Product");
const User = require("./models/User");
const Admin = require("./models/Admin");
const authMiddleware = require("./middleware/auth");

const app = express();

// Robust CORS Handling for Vercel
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Allow any origin that is localhost or a vercel.app domain
  if (origin && (origin.includes("localhost") || origin.endsWith(".vercel.app"))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Immediately respond to preflight requests
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.get("/", (req, res) => {
  res.send("🚀 SK Inventory Backend is Running!");
});

app.use(express.json());



const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ CRITICAL: MONGO_URI is not defined in environment variables!");
}

// Optimization for Serverless (Vercel)
mongoose.set("bufferCommands", false);

let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      serverSelectionTimeoutMS: 5000,
    };

    cached.promise = mongoose.connect(MONGO_URI, opts).then((mongoose) => {
      console.log("✅ MongoDB Connected");
      return mongoose;
    }).catch((err) => {
      console.error("❌ MongoDB Connection Error:", err.message);
      throw err;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

// Middleware to ensure DB connection
const checkDbConnection = async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error("Database connection failed in middleware:", error);
    return res.status(503).json({
      error: "Database not connected",
      details: "The server failed to connect to MongoDB. Please check MONGO_URI and IP Whitelist.",
      reason: error.message
    });
  }
};

// Health Check
app.get("/health", (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? "Connected" : "Disconnected";
  res.json({
    status: "ok",
    database: dbStatus,
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV
  });
});


// Diagnostic DB Test
app.get("/test-db", async (req, res) => {
  try {
    const uri = process.env.MONGO_URI || "";
    const maskedUri = uri ? `${uri.substring(0, 15)}...${uri.substring(uri.length - 5)}` : "MISSING";

    // Attempt a direct ping/connection check
    const status = mongoose.connection.readyState;
    const states = { 0: "Disconnected", 1: "Connected", 2: "Connecting", 3: "Disconnecting" };

    if (status === 1) {
      return res.json({
        success: true,
        message: "Database is already connected!",
        uriStatus: maskedUri !== "MISSING" ? "URI exists" : "URI missing"
      });
    }

    // Try a direct connect with short timeout
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 3000 });

    res.json({
      success: true,
      message: "Direct connection attempt successful!",
      uri: maskedUri
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
      code: err.code,
      details: "If you see 'IP not whitelisted', go to MongoDB Atlas -> Network Access and add 0.0.0.0/0",
      uriPrefix: process.env.MONGO_URI ? process.env.MONGO_URI.substring(0, 10) : "empty"
    });
  }
});

// ========== ADMIN AUTHENTICATION ==========

// Register Admin
app.post("/admin/register", checkDbConnection, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ $or: [{ email }, { username }] });
    if (existingAdmin) {
      return res.status(400).json({ error: "Admin already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create admin
    const admin = await Admin.create({
      username,
      email,
      password: hashedPassword,
    });

    // Generate token
    const token = jwt.sign(
      { id: admin._id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "Admin registered successfully",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Failed to register admin", details: error.message });
  }
});

// Login Admin
app.post("/admin/login", checkDbConnection, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }

    // Find admin
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate token
    const token = jwt.sign(
      { id: admin._id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Failed to login", details: error.message });
  }
});

// Get Admin Profile (Protected)
app.get("/admin/profile", authMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select("-password");
    res.json(admin);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch profile", details: error.message });
  }
});

// ========== PRODUCT ENDPOINTS (Protected) ==========

// Get All Products
app.get("/products", checkDbConnection, async (req, res) => {
  try {
    const products = await Product.find().sort({ expiryDate: 1 });
    res.json(products);
  } catch (error) {
    console.error("Fetch products error:", error);
    res.status(500).json({ error: "Failed to fetch products", details: error.message });
  }
});

// Get Single Product
app.get("/product/:id", checkDbConnection, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product", details: error.message });
  }
});

// Add Product (Protected)
app.post("/product", authMiddleware, checkDbConnection, async (req, res) => {
  try {
    const { name, category, quantity, price, expiryDate, notifyBeforeDays } = req.body;

    // Validation
    if (!name || !quantity || price === undefined || !expiryDate || !notifyBeforeDays) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const product = await Product.create({
      name,
      category,
      quantity,
      price,
      expiryDate,
      notifyBeforeDays,
    });

    res.status(201).json({ message: "Product Added", product });
  } catch (error) {
    res.status(500).json({ error: "Failed to add product", details: error.message });
  }
});

// Update Product (Protected)
app.put("/product/:id", authMiddleware, checkDbConnection, async (req, res) => {
  try {
    const { name, category, quantity, price, expiryDate, notifyBeforeDays } = req.body;

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { name, category, quantity, price, expiryDate, notifyBeforeDays },
      { new: true, runValidators: true }
    );

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product Updated", product });
  } catch (error) {
    res.status(500).json({ error: "Failed to update product", details: error.message });
  }
});

// Delete Product (Protected)
app.delete("/product/:id", authMiddleware, checkDbConnection, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product Deleted" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete product", details: error.message });
  }
});

// ========== USER/TOKEN ENDPOINTS ==========

// Save FCM Token
app.post("/token", checkDbConnection, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Check if token already exists
    const existingUser = await User.findOne({ fcmToken: token });
    if (existingUser) {
      return res.json({ message: "Token already registered" });
    }

    await User.create({ fcmToken: token });
    res.status(201).json({ message: "Token Saved" });
  } catch (error) {
    res.status(500).json({ error: "Failed to save token" });
  }
});

// ========== SERVER START ==========

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

