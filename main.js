// main.js

let database;
const expectedMasterKeyHash = "c6339ae965835fdb58104f4843dda0414dba01fdbedf82b4c4a2963a3b29421e"

let totpSecret;
let masterKey = "";

async function initializeDatabase() {
    const SQL = await initSqlJs({ locateFile: filename => `sql-wasm.wasm` });
    database = new SQL.Database();

    database.run(`
        CREATE TABLE IF NOT EXISTS passwords (
            app TEXT,
            password TEXT
        );
    `);

    console.log("Database initialized!");
}

function generateQRCode(secret) {
    const otpauthUrl = `otpauth://totp/YourAppName?secret=${secret}&issuer=YourIssuerName`;
    QRCode.toDataURL(otpauthUrl, function (err, url) {
        if (err) return console.error("QR code error:", err);
        const qrImage = document.createElement("img");
        qrImage.src = url;
        qrImage.alt = "QR Code for 2FA";
        document.body.appendChild(qrImage);
        alert("Scan this QR code in your authenticator app!");
    });
}

function verify2FA(code) {
    return otplib.authenticator.check(code, totpSecret);
}

function hashMasterPassword(password) {
    return CryptoJS.SHA256(password).toString();
}

function updateDashboard(key) {
    const tableBody = document.getElementById("password-table").querySelector("tbody");
    tableBody.innerHTML = "";

    const aes = new AES256(key);
    const stmt = database.prepare("SELECT * FROM passwords");

    while (stmt.step()) {
        const row = stmt.getAsObject();
        const decryptedPassword = aes.decrypt(row.password);

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${row.app}</td>
            <td><span class="password-text">••••••</span><button class="toggle-password">👁️</button><span class="real-password hidden">${decryptedPassword}</span></td>
            <td><button class="delete-btn" data-app="${row.app}">Delete</button></td>
        `;
        tableBody.appendChild(tr);
    }

    stmt.free();

    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", () => {
            const app = button.dataset.app;
            const stmt = database.prepare("DELETE FROM passwords WHERE app = ?");
            stmt.run([app]);
            stmt.free();
            updateDashboard(key);
        });
    });

    document.querySelectorAll(".toggle-password").forEach(btn => {
        btn.addEventListener("click", () => {
            const real = btn.nextElementSibling;
            const masked = btn.previousElementSibling;
            real.classList.toggle("hidden");
            masked.classList.toggle("hidden");
        });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initializeDatabase();

    document.getElementById("login-form").addEventListener("submit", function (event) {
        event.preventDefault();
        const masterPassword = document.getElementById("master-password").value;
        const hashedPassword = hashMasterPassword(masterPassword);
        const totpCode = document.getElementById("totp-code").value;

        if (hashedPassword === expectedMasterKeyHash) {
            masterKey = masterPassword;

            if (!totpSecret) {
                totpSecret = otplib.authenticator.generateSecret();
                generateQRCode(totpSecret);
            }

            if (verify2FA(totpCode)) {
                alert("Login successful!");
                document.getElementById("login-screen").classList.add("hidden");
                document.getElementById("dashboard").classList.remove("hidden");
                document.getElementById("logout-btn").classList.remove("hidden");
            } else alert("Invalid 2FA code.");
        } else alert("Incorrect master password.");
    });

    document.getElementById("add-password-btn").addEventListener("click", () => {
        const app = prompt("Enter Application Name:");
        const password = prompt("Enter Password:");
    
        if (app && password) {
            const aes = new AES256(masterKey);  // Encrypt using the master password
            const encryptedPassword = aes.encrypt(password);
    
            // Insert encrypted password into the database
            const stmt = database.prepare("INSERT INTO passwords (app, password) VALUES (?, ?)");
            stmt.run([app, encryptedPassword]);
            stmt.free();
    
            alert(`Password added for ${app}`);
            updateDashboard(masterKey);  // Refresh the dashboard
        }
    });
    document.getElementById("find-password-btn").addEventListener("click", () => {
        const app = prompt("Enter Application Name to Search:");
        if (app) {
            const aes = new AES256(masterKey);  // Decrypt using the master password
            const stmt = database.prepare("SELECT * FROM passwords WHERE app = ?");
            stmt.bind([app]);
    
            const results = [];
            while (stmt.step()) {
                const row = stmt.getAsObject();
                const decryptedPassword = aes.decrypt(row.password);  // Decrypt password
    
                // Log decrypted password for debugging
                console.log(`Found password for ${app}: ${decryptedPassword}`);
    
                results.push({ app: row.app, password: decryptedPassword });
            }
            stmt.free();
    
            if (results.length > 0) {
                alert(`Passwords for ${app}: ${results.map(r => r.password).join(", ")}`);
            } else {
                alert(`No passwords found for ${app}.`);
            }
        }
    });
    
       

    document.getElementById("delete-password-btn").addEventListener("click", () => {
        const app = prompt("Enter Application to Delete:");
        const stmt = database.prepare("DELETE FROM passwords WHERE app = ?");
        stmt.run([app]);
        stmt.free();
        updateDashboard(masterKey);
    });

    document.getElementById("update-password-btn").addEventListener("click", () => {
        const app = prompt("App to update:");
        const newPassword = prompt("New password:");
        const aes = new AES256(masterKey);
        const encrypted = aes.encrypt(newPassword);
        const del = database.prepare("DELETE FROM passwords WHERE app = ?");
        del.run([app]);
        del.free();
        const ins = database.prepare("INSERT INTO passwords (app, password) VALUES (?, ?)");
        ins.run([app, encrypted]);
        ins.free();
        updateDashboard(masterKey);
    });

    document.getElementById("logout-btn").addEventListener("click", () => {
        document.getElementById("login-screen").classList.remove("hidden");
        document.getElementById("dashboard").classList.add("hidden");
        document.getElementById("logout-btn").classList.add("hidden");
    });

    // Export passwords to JSON file
    document.getElementById("export-btn")?.addEventListener("click", () => {
        const stmt = database.prepare("SELECT * FROM passwords");
        const data = [];
        while (stmt.step()) data.push(stmt.getAsObject());
        stmt.free();
        const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "backup.json";
        a.click();
    });

    // Import passwords from JSON file
    document.getElementById("import-btn")?.addEventListener("change", (e) => {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = () => {
            const data = JSON.parse(reader.result);
            data.forEach(entry => {
                const stmt = database.prepare("INSERT INTO passwords (app, password) VALUES (?, ?)");
                stmt.run([entry.app, entry.password]);
                stmt.free();
            });
            updateDashboard(masterKey);
        };
        reader.readAsText(file);
    });
});