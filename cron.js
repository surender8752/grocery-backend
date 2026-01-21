const cron = require("node-cron");
const Product = require("./models/Product");
const User = require("./models/User");
const { admin, firebaseInitialized } = require("./firebase");

cron.schedule("0 9 * * *", async () => {
  if (!firebaseInitialized) {
    console.log("⚠️ Skipping notification cron - Firebase not initialized");
    return;
  }

  const products = await Product.find();
  const users = await User.find();
  const today = new Date();

  for (let p of products) {
    const diff =
      (new Date(p.expiryDate) - today) / (1000 * 60 * 60 * 24);

    if (diff <= p.notifyBeforeDays && diff > 0) {
      for (let u of users) {
        try {
          await admin.messaging().send({
            token: u.fcmToken,
            notification: {
              title: "⚠️ Expiry Alert",
              body: `${p.name} ${Math.ceil(diff)} din me expire hone wala hai`
            }
          });
        } catch (error) {
          console.error("Error sending notification:", error);
        }
      }
    }
  }
});
