// routes/users.js
// Add this to your existing Express backend

const express = require("express");
const router = express.Router();

// POST /users/fcmToken
// Called by iOS app whenever FCM token is refreshed
router.post("/fcmToken", async (req, res) => {
  const { userId, fcmToken } = req.body;

  if (!userId || !fcmToken) {
    return res.status(400).json({ error: "userId and fcmToken required" });
  }

  try {
    // TODO: Save to your DB — example shown for a generic db module
    // await db.collection("users").updateOne(
    //   { userId },
    //   { $set: { fcmToken, updatedAt: new Date() } },
    //   { upsert: true }
    // );

    console.log(`✅ FCM token saved for user ${userId}`);
    res.json({ success: true });
  } catch (err) {
    console.error("FCM token save error:", err);
    res.status(500).json({ error: "Failed to save token" });
  }
});

module.exports = router;