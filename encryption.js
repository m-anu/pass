class AES256 {
    constructor(key) {
        this.key = CryptoJS.SHA256(key).toString(); // Hash the key for uniformity
        this.iv = CryptoJS.enc.Hex.parse('2cdf253cf89bbaa91c4141a3fc26b4eb'); // Static IV (matches your Python implementation)
    }

    encrypt(plaintext) {
        const encrypted = CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Hex.parse(this.key), {
            iv: this.iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString(); // Return the encrypted text as a string
    }

    decrypt(ciphertext) {
        try {
            const decrypted = CryptoJS.AES.decrypt(ciphertext, CryptoJS.enc.Hex.parse(this.key), {
                iv: this.iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            return decrypted.toString(CryptoJS.enc.Utf8); // Decode to plaintext
        } catch (error) {
            console.error("Decryption failed:", error);
            return ""; // Return an empty string if decryption fails
        }
    }
}

// Function to add a password to the database
function addPassword(db, app, plaintextPassword, key) {
    const aes = new AES256(key); // Create an instance with the master password
    const encryptedPassword = aes.encrypt(plaintextPassword);

    const stmt = db.prepare("INSERT INTO passwords (app, password) VALUES (?, ?)");
    stmt.run([app, encryptedPassword]);
    stmt.free();
    console.log(`Encrypted password added for ${app}`);
}

// Function to find a password in the database
function findPassword(db, app, key) {
    const stmt = db.prepare("SELECT * FROM passwords WHERE app = ?");
    stmt.bind([app]);

    const aes = new AES256(key); // Create an instance with the master password
    const results = [];

    while (stmt.step()) {
        const row = stmt.getAsObject();
        row.password = aes.decrypt(row.password); // Decrypt the password
        results.push(row);
    }

    stmt.free();
    return results; // Return decrypted passwords
}

// Function to update the password dashboard
function updateDashboard(key) {
    const tableBody = document.getElementById("password-table").querySelector("tbody");
    tableBody.innerHTML = ""; // Clear the table content

    const stmt = database.prepare("SELECT * FROM passwords");
    const aes = new AES256(key); // Create an instance with the master password

    while (stmt.step()) {
        const row = stmt.getAsObject();
        const decryptedPassword = aes.decrypt(row.password); // Decrypt the password

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${row.app}</td>
            <td>${decryptedPassword}</td>
            <td>
                <button class="delete-btn" data-app="${row.app}">Delete</button>
            </td>
        `;
        tableBody.appendChild(tr);
    }

    stmt.free();

    // Attach delete functionality to buttons dynamically
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function () {
            deletePassword(database, button.dataset.app); // Delete the password
            updateDashboard(key); // Refresh the dashboard
        });
    });
}

// Function to delete a password
function deletePassword(db, app) {
    const stmt = db.prepare("DELETE FROM passwords WHERE app = ?");
    stmt.run([app]);
    stmt.free();
    console.log(`Password for ${app} deleted.`);
}
