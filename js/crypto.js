async function getKey(password) {

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
            salt: enc.encode("kalpass_salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

window.encryptVault = async function (text, password) {

    const key = await getKey(password);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const enc = new TextEncoder();

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(text)
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);

    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...combined));
}

window.decryptVault = async function (data, password) {

    const bytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));

    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);

    const key = await getKey(password);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
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

