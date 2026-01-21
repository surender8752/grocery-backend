const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  fcmToken: String
});

module.exports = mongoose.model("User", userSchema);
