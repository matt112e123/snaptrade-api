import { Router, Request, Response } from "express";
import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const router = Router();

// POST /users/fcmToken
// Called by iOS app to save OneSignal Player ID
router.post("/fcmToken", async (req: Request, res: Response) => {
  const { userId, fcmToken } = req.body as { userId: string; fcmToken: string };

  if (!userId || !fcmToken) {
    return res.status(400).json({ error: "userId and fcmToken required" });
  }

  try {
    await pool.query(
      "UPDATE snaptrade_users SET onesignal_player_id = $1 WHERE user_id = $2",
      [fcmToken, userId]
    );
    console.log(`✅ OneSignal Player ID saved for user ${userId}`);
    return res.json({ success: true });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("FCM token save error:", message);
    return res.status(500).json({ error: "Failed to save token" });
  }
});

export default router;