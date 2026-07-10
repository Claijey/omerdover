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

function saveDB() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
    } catch (e) {
        console.error("Error writing database file:", e);
    }
}

// Cookie Helper
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
        if (sessionId && db.sessions[sessionId]) {
            const userKey = db.sessions[sessionId];
            const user = db.users[userKey];
            if (user) {
                return sendJSON(200, { loggedIn: true, username: user.username, score: user.score });
            }
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

        // Check if user already exists
        if (db.users[userKey]) {
            return sendJSON(400, { success: false, message: 'Username is already taken!' });
        }

        // Generate secure random session token
        const token = crypto.randomBytes(32).toString('hex');

        // Store user and map session
        db.users[userKey] = {
            username: trimmedUser,
            score: 0,
            token: token
        };
        db.sessions[token] = userKey;
        saveDB();

        // Set HttpOnly long-lived session cookie (10 years)
        const cookieVal = `sessionId=${token}; Max-Age=${10 * 365 * 24 * 60 * 60}; Path=/; SameSite=Lax; HttpOnly`;
        return sendJSON(200, { success: true, username: trimmedUser, score: 0 }, { 'Set-Cookie': cookieVal });
    }

    // Increment whip count
    if (pathname === '/api/whip' && req.method === 'POST') {
        const sessionId = getCookie(req, 'sessionId');
        if (sessionId && db.sessions[sessionId]) {
            const userKey = db.sessions[sessionId];
            const user = db.users[userKey];
            if (user) {
                user.score++;
                saveDB();
                return sendJSON(200, { success: true, score: user.score });
            }
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
        const sessionId = getCookie(req, 'sessionId');
        if (sessionId) {
            delete db.sessions[sessionId];
            saveDB();
        }
        // Clear cookie
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
