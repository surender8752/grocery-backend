const mongoose = require("mongoose");

const productSchema = new mongoose.Schema({
  name: String,
  quantity: Number,
  expiryDate: Date,
  notifyBeforeDays: Number
});

module.exports = mongoose.model("Product", productSchema);
