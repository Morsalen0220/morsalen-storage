import { initializeApp, getApps } from "firebase/app"
import {
    doc,
    getDoc,
    getFirestore,
    serverTimestamp,
    setDoc,
    deleteDoc,
    Timestamp,
} from "firebase/firestore"

const firebaseConfig = {
    apiKey: "AIzaSyDY6xI7RrS7K-yx9Mr13-StQnJFil1KEEc",
    authDomain: "telegrm-b1274.firebaseapp.com",
    projectId: "telegrm-b1274",
    storageBucket: "telegrm-b1274.firebasestorage.app",
    messagingSenderId: "381760932350",
    appId: "1:381760932350:web:2f4cb1ccb96851a70198af",
    measurementId: "G-EW9ZMYBG0M",
}

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig)
const db = getFirestore(app)
const sessionDocRef = doc(db, "single_user_auth", "config")

const PIN_PATTERN = /^[0-9]{4,12}$/
const PBKDF2_ITERATIONS = 210000

type StoredSessionDoc = {
    version: number
    algorithm: "AES-GCM"
    iterations: number
    salt: string
    iv: string
    ciphertext: string
    updatedAt?: Timestamp
}

type CloudSessionPayload = {
    session: string
    phone: string
    storagePeer?: string
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = ""
    for (const b of bytes) {
        binary += String.fromCharCode(b)
    }
    return btoa(binary)
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
        out[i] = binary.charCodeAt(i)
    }
    return out
}

async function deriveAesKey(pin: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
    const keyMaterial = await window.crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, [
        "deriveKey",
    ])
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt,
            iterations,
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    )
}

function validatePin(pin: string) {
    if (!PIN_PATTERN.test(pin)) {
        throw new Error("PIN must be 4-12 digits.")
    }
}

export function isPinFormatValid(pin: string): boolean {
    return PIN_PATTERN.test(pin)
}

export async function hasCloudSession(): Promise<boolean> {
    const snap = await getDoc(sessionDocRef)
    return snap.exists()
}

export async function saveCloudSession(pin: string, session: string, phone: string, storagePeer?: string): Promise<void> {
    validatePin(pin)
    if (!session || session.trim().length < 8) {
        throw new Error("Telegram session string is missing.")
    }
    const payload: CloudSessionPayload = { session, phone, storagePeer }
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
    const salt = window.crypto.getRandomValues(new Uint8Array(16))
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const key = await deriveAesKey(pin, salt, PBKDF2_ITERATIONS)
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payloadBytes))

    const toStore: StoredSessionDoc = {
        version: 1,
        algorithm: "AES-GCM",
        iterations: PBKDF2_ITERATIONS,
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(encrypted),
    }

    await setDoc(
        sessionDocRef,
        {
            ...toStore,
            updatedAt: serverTimestamp(),
        },
        { merge: true },
    )
}

export async function loadCloudSession(pin: string): Promise<CloudSessionPayload> {
    validatePin(pin)
    const snap = await getDoc(sessionDocRef)
    if (!snap.exists()) {
        throw new Error("No cloud session is configured yet.")
    }
    const data = snap.data() as StoredSessionDoc
    if (!data || data.version !== 1 || data.algorithm !== "AES-GCM") {
        throw new Error("Stored cloud session format is invalid.")
    }

    const salt = base64ToBytes(data.salt)
    const iv = base64ToBytes(data.iv)
    const ciphertext = base64ToBytes(data.ciphertext)
    const key = await deriveAesKey(pin, salt, data.iterations || PBKDF2_ITERATIONS)

    let decrypted: ArrayBuffer
    try {
        decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)
    } catch {
        throw new Error("PIN is incorrect.")
    }

    const json = new TextDecoder().decode(new Uint8Array(decrypted))
    const payload = JSON.parse(json) as CloudSessionPayload
    if (!payload?.session) {
        throw new Error("Stored cloud session payload is invalid.")
    }
    return payload
}

export async function clearCloudSession(pin: string): Promise<void> {
    await loadCloudSession(pin)
    await deleteDoc(sessionDocRef)
}
