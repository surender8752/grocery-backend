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

// CORS Configuration
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://grocery-frontend-ocon.vercel.app"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());


const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// ========== ADMIN AUTHENTICATION ==========

// Register Admin
app.post("/admin/register", async (req, res) => {
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
    res.status(500).json({ error: "Failed to register admin" });
  }
});

// Login Admin
app.post("/admin/login", async (req, res) => {
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
    res.status(500).json({ error: "Failed to login" });
  }
});

// Get Admin Profile (Protected)
app.get("/admin/profile", authMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select("-password");
    res.json(admin);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// ========== PRODUCT ENDPOINTS (Protected) ==========

// Get All Products
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ expiryDate: 1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Get Single Product
app.get("/product/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// Add Product (Protected)
app.post("/product", authMiddleware, async (req, res) => {
  try {
    const { name, quantity, expiryDate, notifyBeforeDays } = req.body;

    // Validation
    if (!name || !quantity || !expiryDate || !notifyBeforeDays) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const product = await Product.create({
      name,
      quantity,
      expiryDate,
      notifyBeforeDays,
    });

    res.status(201).json({ message: "Product Added", product });
  } catch (error) {
    res.status(500).json({ error: "Failed to add product" });
  }
});

// Update Product (Protected)
app.put("/product/:id", authMiddleware, async (req, res) => {
  try {
    const { name, quantity, expiryDate, notifyBeforeDays } = req.body;

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { name, quantity, expiryDate, notifyBeforeDays },
      { new: true, runValidators: true }
    );

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product Updated", product });
  } catch (error) {
    res.status(500).json({ error: "Failed to update product" });
  }
});

// Delete Product (Protected)
app.delete("/product/:id", authMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product Deleted" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// ========== USER/TOKEN ENDPOINTS ==========

// Save FCM Token
app.post("/token", async (req, res) => {
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

