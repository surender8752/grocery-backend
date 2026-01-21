const admin = require("firebase-admin");

let firebaseInitialized = false;

try {
  const serviceAccount = require("./firebase-key.json");
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  firebaseInitialized = true;
  console.log("✅ Firebase Admin initialized");
} catch (error) {
  console.warn("⚠️ Firebase not initialized - notifications will not work");
  console.warn("Add firebase-key.json to enable push notifications");
}

module.exports = { admin, firebaseInitialized };
