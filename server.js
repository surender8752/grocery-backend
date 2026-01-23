require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const csv = require("csv-parser");
const { Readable } = require("stream");
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

// Configure Multer for CSV uploads
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV files are allowed'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

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
app.get("/admin/profile", authMiddleware, checkDbConnection, async (req, res) => {
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

// Search Products
app.get("/products/search", checkDbConnection, async (req, res) => {
  try {
    const { q } = req.query;

    if (!q || q.trim() === "") {
      return res.json([]);
    }

    const searchRegex = new RegExp(q.trim(), "i");

    const products = await Product.find({
      $or: [
        { name: searchRegex },
        { category: searchRegex },
        { subcategory: searchRegex }
      ]
    }).sort({ expiryDate: 1 });

    res.json(products);
  } catch (error) {
    console.error("Search products error:", error);
    res.status(500).json({ error: "Failed to search products", details: error.message });
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
    const { name, category, subcategory, quantity, weight, price, expiryDate, notifyBeforeDays } = req.body;

    // Validation
    if (!name || !quantity || price === undefined || !expiryDate || !notifyBeforeDays) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check for duplicate product (case-insensitive)
    const existingProduct = await Product.findOne({
      name: { $regex: new RegExp(`^${name}$`, 'i') }
    });

    if (existingProduct) {
      return res.status(409).json({
        error: "Duplicate product",
        message: `Product "${name}" already exists in the inventory.`,
        existingProduct: {
          id: existingProduct._id,
          name: existingProduct.name,
          category: existingProduct.category,
          quantity: existingProduct.quantity
        }
      });
    }

    const product = await Product.create({
      name,
      category,
      subcategory,
      quantity,
      weight,
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
    const { name, category, subcategory, quantity, weight, price, expiryDate, notifyBeforeDays } = req.body;

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { name, category, subcategory, quantity, weight, price, expiryDate, notifyBeforeDays },
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

// Upload Products from CSV (Protected)
app.post("/products/upload-csv", authMiddleware, upload.single('csvFile'), checkDbConnection, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const results = [];
    const errors = [];
    const skipped = [];
    let lineNumber = 1; // Start from 1 (header is line 0)

    // Convert buffer to readable stream
    const bufferStream = Readable.from(req.file.buffer.toString());

    // Parse CSV
    await new Promise((resolve, reject) => {
      bufferStream
        .pipe(csv())
        .on('data', (data) => {
          lineNumber++;
          results.push({ ...data, lineNumber });
        })
        .on('end', resolve)
        .on('error', reject);
    });

    if (results.length === 0) {
      return res.status(400).json({ error: "CSV file is empty or invalid" });
    }

    const successfulProducts = [];

    // Process each row
    for (const row of results) {
      try {
        const { name, category, subcategory, quantity, weight, price, expiryDate, notifyBeforeDays } = row;

        // Validate required fields
        if (!name || !quantity || price === undefined || !expiryDate || !notifyBeforeDays) {
          errors.push({
            line: row.lineNumber,
            data: row,
            error: "Missing required fields (name, quantity, price, expiryDate, notifyBeforeDays)"
          });
          continue;
        }

        // Validate data types
        const parsedQuantity = Number(quantity);
        const parsedWeight = weight ? Number(weight) : undefined;
        const parsedPrice = Number(price);
        const parsedNotifyDays = Number(notifyBeforeDays);

        if (isNaN(parsedQuantity) || isNaN(parsedPrice) || isNaN(parsedNotifyDays)) {
          errors.push({
            line: row.lineNumber,
            data: row,
            error: "Invalid number format for quantity, price, or notifyBeforeDays"
          });
          continue;
        }

        if (parsedWeight !== undefined && isNaN(parsedWeight)) {
          errors.push({
            line: row.lineNumber,
            data: row,
            error: "Invalid number format for weight"
          });
          continue;
        }

        // Validate date
        const parsedDate = new Date(expiryDate);
        if (isNaN(parsedDate.getTime())) {
          errors.push({
            line: row.lineNumber,
            data: row,
            error: "Invalid date format for expiryDate (use YYYY-MM-DD)"
          });
          continue;
        }

        // Check for duplicate (case-insensitive)
        const existingProduct = await Product.findOne({
          name: { $regex: new RegExp(`^${name.trim()}$`, 'i') }
        });

        if (existingProduct) {
          skipped.push({
            line: row.lineNumber,
            name: name,
            reason: "Product already exists"
          });
          continue;
        }

        // Create product
        const product = await Product.create({
          name: name.trim(),
          category: category?.trim() || '',
          subcategory: subcategory?.trim() || '',
          quantity: parsedQuantity,
          weight: parsedWeight,
          price: parsedPrice,
          expiryDate: parsedDate,
          notifyBeforeDays: parsedNotifyDays
        });

        successfulProducts.push(product);

      } catch (error) {
        errors.push({
          line: row.lineNumber,
          data: row,
          error: error.message
        });
      }
    }

    res.json({
      message: "CSV processing completed",
      summary: {
        total: results.length,
        successful: successfulProducts.length,
        failed: errors.length,
        skipped: skipped.length
      },
      successfulProducts,
      errors,
      skipped
    });

  } catch (error) {
    console.error("CSV upload error:", error);
    res.status(500).json({ error: "Failed to process CSV file", details: error.message });
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

