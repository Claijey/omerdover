const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 8080; // Standard local port for testing
const isVercel = process.env.VERCEL;
const DB_FILE = isVercel ? '/tmp/db.json' : path.join(process.cwd(), 'db.json');

// Initialize database
let db = { users: {}, sessions: {} };
if (fs.existsSync(DB_FILE)) {
    try {
        db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        console.error("Error reading database file, resetting:", e);
    }
}

// Make sure users property is initialized
if (!db.users) db.users = {};

function saveDB() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
    } catch (e) {
        console.error("Error writing database file:", e);
    }
}

// Cookie Helpers
function getCookie(req, name) {
    const list = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const parts = cookie.split('=');
            list[parts.shift().trim()] = decodeURIComponent(parts.join('='));
        });
    }
    return list[name];
}

// Encode session data into a base64 cookie token
function encodeSession(username, score) {
    const rawStr = `${username}|${score}`;
    return Buffer.from(rawStr, 'utf8').toString('base64');
}

// Decode session data from a base64 cookie token
function decodeSession(token) {
    if (!token) return null;
    try {
        const rawStr = Buffer.from(token, 'base64').toString('utf8');
        const parts = rawStr.split('|');
        if (parts.length === 2) {
            return { username: parts[0], score: parseInt(parts[1], 10) || 0 };
        }
    } catch (e) {
        console.error("Failed to decode session token:", e);
    }
    return null;
}

// JSON body parser helper
function readJSONBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body || '{}'));
            } catch (e) {
                resolve({});
            }
        });
    });
}

// Core Request Handler
const handler = async (req, res) => {
    const sendJSON = (status, obj, headers = {}) => {
        res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
        res.end(JSON.stringify(obj));
    };

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // --- API ENDPOINTS ---

    // Get current logged-in user profile
    if (pathname === '/api/me' && req.method === 'GET') {
        const sessionId = getCookie(req, 'sessionId');
        const session = decodeSession(sessionId);
        if (session) {
            const { username, score } = session;
            const userKey = username.toLowerCase();
            
            // Re-sync with container database
            if (!db.users[userKey]) {
                db.users[userKey] = { username, score };
                saveDB();
            } else if (db.users[userKey].score < score) {
                db.users[userKey].score = score;
                saveDB();
            }
            
            return sendJSON(200, { loggedIn: true, username: db.users[userKey].username, score: db.users[userKey].score });
        }
        return sendJSON(200, { loggedIn: false });
    }

    // Sign up a user
    if (pathname === '/api/signup' && req.method === 'POST') {
        const { username } = await readJSONBody(req);
        if (!username || typeof username !== 'string' || username.trim().length === 0) {
            return sendJSON(400, { success: false, message: 'Invalid username' });
        }

        const trimmedUser = username.trim().substring(0, 20); // Cap username length
        const userKey = trimmedUser.toLowerCase();

        // Check if user already exists in local DB
        if (db.users[userKey]) {
            return sendJSON(400, { success: false, message: 'Username is already taken!' });
        }

        // Store user locally
        db.users[userKey] = {
            username: trimmedUser,
            score: 0
        };
        saveDB();

        // Generate base64 session token
        const token = encodeSession(trimmedUser, 0);

        // Set HttpOnly long-lived session cookie (10 years)
        const cookieVal = `sessionId=${token}; Max-Age=${10 * 365 * 24 * 60 * 60}; Path=/; SameSite=Lax; HttpOnly`;
        return sendJSON(200, { success: true, username: trimmedUser, score: 0 }, { 'Set-Cookie': cookieVal });
    }

    // Increment whip count
    if (pathname === '/api/whip' && req.method === 'POST') {
        const sessionId = getCookie(req, 'sessionId');
        const session = decodeSession(sessionId);
        if (session) {
            const { username, score } = session;
            const userKey = username.toLowerCase();

            // Re-sync user record in container memory if missing
            if (!db.users[userKey]) {
                db.users[userKey] = { username, score };
            } else if (db.users[userKey].score < score) {
                db.users[userKey].score = score;
            }

            // Increment score
            db.users[userKey].score++;
            saveDB();

            const newScore = db.users[userKey].score;
            const token = encodeSession(username, newScore);

            // Update session cookie with the new score
            const cookieVal = `sessionId=${token}; Max-Age=${10 * 365 * 24 * 60 * 60}; Path=/; SameSite=Lax; HttpOnly`;
            return sendJSON(200, { success: true, score: newScore }, { 'Set-Cookie': cookieVal });
        }
        return sendJSON(401, { success: false, message: 'Unauthorized session' });
    }

    // Get top 10 leaderboard
    if (pathname === '/api/leaderboard' && req.method === 'GET') {
        const leaderboard = Object.values(db.users)
            .map(u => ({ username: u.username, score: u.score }))
            .sort((a, b) => b.score - a.score)
            .slice(0, 10);
        return sendJSON(200, { success: true, users: leaderboard });
    }

    // Logout
    if (pathname === '/api/logout' && req.method === 'POST') {
        // Clear session cookie
        const cookieVal = `sessionId=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly`;
        return sendJSON(200, { success: true }, { 'Set-Cookie': cookieVal });
    }

    // --- STATIC FILES SERVING (Only used locally as Vercel serves static files directly) ---
    if (!isVercel && req.method === 'GET') {
        let filename = pathname === '/' ? 'index.html' : pathname.substring(1);
        let filePath = path.join(process.cwd(), filename);

        // Basic security check (prevent directory traversal)
        const relative = path.relative(process.cwd(), filePath);
        const isSafe = relative && !relative.startsWith('..') && !path.isAbsolute(relative);

        if (isSafe && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
            const ext = path.extname(filePath).toLowerCase();
            const mimeTypes = {
                '.html': 'text/html',
                '.css': 'text/css',
                '.js': 'text/javascript',
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.gif': 'image/gif',
                '.mp3': 'audio/mpeg',
                '.json': 'application/json'
            };
            const contentType = mimeTypes[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            fs.createReadStream(filePath).pipe(res);
            return;
        }
    }

    // Fallback 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
};

if (isVercel) {
    module.exports = handler;
} else {
    const server = http.createServer(handler);
    server.listen(PORT, () => {
        console.log(`omerdover server running at http://localhost:${PORT}/`);
        console.log(`Working directory: ${process.cwd()}`);
    });
}
