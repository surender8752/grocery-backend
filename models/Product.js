const mongoose = require("mongoose");

const productSchema = new mongoose.Schema({
  name: String,
  category: String,
  subcategory: String,
  quantity: Number,
  weight: Number,
  price: Number,
  expiryDate: Date,
  notifyBeforeDays: Number
});

module.exports = mongoose.models.Product || mongoose.model("Product", productSchema);
