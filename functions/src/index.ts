import * as crypto from "node:crypto";
import {initializeApp} from "firebase-admin/app";
import {getFirestore, Timestamp} from "firebase-admin/firestore";
import {onRequest} from "firebase-functions/v2/https";
import {defineSecret} from "firebase-functions/params";

initializeApp();
const db = getFirestore();

const SESSION_SECRET = defineSecret("SESSION_ENC_KEY");
const DOC_PATH = "single_user_auth/config";
const REGION = "asia-south1";
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

type AuthDoc = {
  pinSalt: string;
  pinHash: string;
  encSession: string;
  iv: string;
  tag: string;
  failedAttempts?: number;
  lockUntil?: Timestamp | null;
  updatedAt: Timestamp;
};

function badRequest(res: any, message: string) {
  res.status(400).json({ok: false, error: message});
}

function validatePin(pin: unknown): pin is string {
  return (
    typeof pin === "string" &&
    /^[0-9]{4,12}$/.test(pin)
  );
}

function derivePinHash(pin: string, salt: Buffer): Buffer {
  return crypto.scryptSync(pin, salt, 32);
}

function encryptSession(session: string, secret: string) {
  const key = crypto.createHash("sha256").update(secret, "utf8").digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(session, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    encSession: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
  };
}

function decryptSession(
  encSession: string,
  ivB64: string,
  tagB64: string,
  secret: string
): string {
  const key = crypto.createHash("sha256").update(secret, "utf8").digest();
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const encrypted = Buffer.from(encSession, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

export const setupPinAndSession = onRequest(
  {region: REGION, secrets: [SESSION_SECRET], cors: true},
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ok: false, error: "Method not allowed"});
      return;
    }

    const pin = req.body?.pin;
    const session = req.body?.session;
    if (!validatePin(pin)) {
      badRequest(res, "PIN must be 4-12 digits.");
      return;
    }
    if (typeof session !== "string" || session.trim().length < 10) {
      badRequest(res, "Session is missing or invalid.");
      return;
    }

    const salt = crypto.randomBytes(16);
    const pinHash = derivePinHash(pin, salt);
    const encrypted = encryptSession(session, SESSION_SECRET.value());

    const payload: AuthDoc = {
      pinSalt: salt.toString("base64"),
      pinHash: pinHash.toString("base64"),
      encSession: encrypted.encSession,
      iv: encrypted.iv,
      tag: encrypted.tag,
      failedAttempts: 0,
      lockUntil: null,
      updatedAt: Timestamp.now(),
    };

    await db.doc(DOC_PATH).set(payload, {merge: true});
    res.json({ok: true});
  }
);

export const loginWithPin = onRequest(
  {region: REGION, secrets: [SESSION_SECRET], cors: true},
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ok: false, error: "Method not allowed"});
      return;
    }

    const pin = req.body?.pin;
    if (!validatePin(pin)) {
      badRequest(res, "Invalid PIN format.");
      return;
    }

    const ref = db.doc(DOC_PATH);
    const snap = await ref.get();
    if (!snap.exists) {
      res.status(404).json({ok: false, error: "PIN/session is not configured."});
      return;
    }

    const data = snap.data() as AuthDoc;

    const nowMs = Date.now();
    const lockUntilMs = data.lockUntil?.toMillis() ?? 0;
    if (lockUntilMs > nowMs) {
      res.status(429).json({ok: false, error: "Temporarily locked. Try again later."});
      return;
    }

    const salt = Buffer.from(data.pinSalt, "base64");
    const expected = Buffer.from(data.pinHash, "base64");
    const actual = derivePinHash(pin, salt);
    const isMatch = actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);

    if (!isMatch) {
      const failedAttempts = (data.failedAttempts ?? 0) + 1;
      const updates: Partial<AuthDoc> = {
        failedAttempts,
      };
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date(nowMs + LOCKOUT_MINUTES * 60 * 1000);
        updates.lockUntil = Timestamp.fromDate(lockUntil);
        updates.failedAttempts = 0;
      }
      await ref.set(updates, {merge: true});
      res.status(401).json({ok: false, error: "PIN is incorrect."});
      return;
    }

    const session = decryptSession(
      data.encSession,
      data.iv,
      data.tag,
      SESSION_SECRET.value()
    );

    await ref.set({failedAttempts: 0, lockUntil: null}, {merge: true});
    res.json({ok: true, session});
  }
);

export const logoutEverywhere = onRequest(
  {region: REGION, secrets: [SESSION_SECRET], cors: true},
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ok: false, error: "Method not allowed"});
      return;
    }

    const pin = req.body?.pin;
    if (!validatePin(pin)) {
      badRequest(res, "Invalid PIN format.");
      return;
    }

    const ref = db.doc(DOC_PATH);
    const snap = await ref.get();
    if (!snap.exists) {
      res.status(404).json({ok: false, error: "No session found."});
      return;
    }
    const data = snap.data() as AuthDoc;

    const salt = Buffer.from(data.pinSalt, "base64");
    const expected = Buffer.from(data.pinHash, "base64");
    const actual = derivePinHash(pin, salt);
    const isMatch = actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
    if (!isMatch) {
      res.status(401).json({ok: false, error: "PIN is incorrect."});
      return;
    }

    await ref.delete();
    res.json({ok: true});
  }
);
