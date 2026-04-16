
//------------------------------------------------------------------------

// ===============================
// 🔐 CONFIG
// ===============================
const VERSION = 1;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const ITERATIONS = 100000;

// ===============================
// 🔑 KEY DERIVATION
// ===============================
async function deriveKey(password, salt) {
    const enc = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// ===============================
// 🔐 ENCRYPT
// ===============================
window.encryptVault = async function (plainText, password) {

    const enc = new TextEncoder();

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(plainText)
    );

    const cipherBytes = new Uint8Array(encrypted);

    const combined = new Uint8Array(
        1 + SALT_LENGTH + IV_LENGTH + cipherBytes.length
    );

    let offset = 0;

    combined[offset++] = VERSION;
    combined.set(salt, offset); offset += SALT_LENGTH;
    combined.set(iv, offset); offset += IV_LENGTH;
    combined.set(cipherBytes, offset);

    return base64Encode(combined);
};

// ===============================
// 🔓 DECRYPT
// ===============================
window.decryptVault = async function (base64Data, password) {

    try {
        const bytes = base64Decode(base64Data);

        let offset = 0;

        const version = bytes[offset++];
        if (version !== VERSION) {
            throw new Error("Unsupported vault version");
        }

        const salt = bytes.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const iv = bytes.slice(offset, offset + IV_LENGTH);
        offset += IV_LENGTH;

        const ciphertext = bytes.slice(offset);

        const key = await deriveKey(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        return new TextDecoder().decode(decrypted);

    } catch (e) {
        console.error("FINAL FAIL:", e);
        throw new Error("Invalid password or corrupted vault");
    }
};

// ===============================
// 🔁 SAFE BASE64
// ===============================
function base64Encode(bytes) {
    let binary = "";
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary);
}

function base64Decode(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}





window.downloadFile = function (filename, data) {

    const blob = new Blob([data], { type: "text/xml" });

    const a = document.createElement("a");

    a.href = URL.createObjectURL(blob);

    a.download = filename;

    a.click();
}

window.copyToClipboard = function (text) {
    navigator.clipboard.writeText(text);
}

