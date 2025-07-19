const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = 'supersecretkey';

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(\`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    balance REAL DEFAULT 0,
    lastMiningClaim INTEGER DEFAULT 0
  )\`);

  db.run(\`CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    reward REAL
  )\`);

  db.run(\`CREATE TABLE claimed_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    task_id INTEGER,
    claimed_at INTEGER
  )\`);

  db.run(\`CREATE TABLE withdraw_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ton_address TEXT,
    amount REAL,
    status TEXT DEFAULT 'pending',
    requested_at INTEGER
  )\`);

  const tasks = [
    { name: 'Join Our Telegram Channel', reward: 0.1 },
    { name: 'Watch Ad', reward: 0.1 },
    { name: 'Follow Twitter', reward: 0.1 },
    { name: 'Retweet', reward: 0.1 }
  ];

  const stmt = db.prepare('INSERT INTO tasks (name, reward) VALUES (?, ?)');
  tasks.forEach(t => stmt.run(t.name, t.reward));
  stmt.finalize();
});

// Helper functions
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Token required' });

  const token = authHeader;
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
    if (err) return res.status(400).json({ message: 'Email already registered' });
    res.json({ message: 'Registered successfully' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '7d' });
    res.json({ token, balance: user.balance });
  });
});

app.post('/api/claim-task', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { taskId } = req.body;

  if (!taskId) return res.status(400).json({ message: 'Task ID required' });

  const now = Date.now();

  // Check if task already claimed by user in last 24 hours
  db.get(
    'SELECT * FROM claimed_tasks WHERE user_id = ? AND task_id = ? AND claimed_at > ?',
    [userId, taskId, now - 24 * 3600 * 1000],
    (err, row) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (row) return res.status(400).json({ message: 'Task already claimed in last 24 hours' });

      // Get task reward
      db.get('SELECT reward FROM tasks WHERE id = ?', [taskId], (err, task) => {
        if (err || !task) return res.status(400).json({ message: 'Invalid task' });

        // Add reward to user balance
        db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [task.reward, userId], function(err) {
          if (err) return res.status(500).json({ message: 'Failed to update balance' });

          // Log claimed task
          db.run('INSERT INTO claimed_tasks (user_id, task_id, claimed_at) VALUES (?, ?, ?)', [userId, taskId, now]);

          // Return updated balance
          db.get('SELECT balance FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) return res.status(500).json({ message: 'Failed to fetch balance' });
            res.json({ message: 'Task claimed successfully', balance: user.balance });
          });
        });
      });
    }
  );
});

app.post('/api/claim-mining', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const now = Date.now();

  // Check last mining claim
  db.get('SELECT lastMiningClaim FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) return res.status(500).json({ message: 'User not found' });
    if (now - user.lastMiningClaim < 24 * 3600 * 1000) {
      return res.status(400).json({ message: 'Mining already claimed in last 24 hours' });
    }

    // Update balance and last mining claim
    db.run('UPDATE users SET balance = balance + ?, lastMiningClaim = ? WHERE id = ?', [0.5, now, userId], function(err) {
      if (err) return res.status(500).json({ message: 'Failed to update balance' });

      db.get('SELECT balance FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ message: 'Failed to fetch balance' });
        res.json({ message: 'Mining claimed successfully', balance: user.balance });
      });
    });
  });
});

app.post('/api/withdraw', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { tonAddress, amount } = req.body;
  if (!tonAddress || !amount) return res.status(400).json({ message: 'TON address and amount required' });
  if (amount <= 0) return res.status(400).json({ message: 'Invalid amount' });

  // Check user balance
  db.get('SELECT balance FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) return res.status(500).json({ message: 'User not found' });
    if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance' });

    const now = Date.now();

    // Insert withdraw request
    db.run(
      'INSERT INTO withdraw_requests (user_id, ton_address, amount, status, requested_at) VALUES (?, ?, ?, ?, ?)',
      [userId, tonAddress, amount, 'pending', now],
      function(err) {
        if (err) return res.status(500).json({ message: 'Failed to submit withdraw request' });

        // Deduct balance
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, userId]);

        res.json({ message: 'Withdraw request submitted' });
      }
    );
  });
});

app.get('/api/admin/withdraw-requests', (req, res) => {
  // TODO: add admin authentication
  db.all('SELECT * FROM withdraw_requests WHERE status = "pending"', (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch requests' });
    res.json(rows);
  });
});

app.post('/api/admin/withdraw-approve', (req, res) => {
  // TODO: add admin authentication
  const { requestId, approve } = req.body;
  if (!requestId) return res.status(400).json({ message: 'Request ID required' });

  const status = approve ? 'approved' : 'rejected';

  db.run('UPDATE withdraw_requests SET status = ? WHERE id = ?', [status, requestId], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to update request status' });
    res.json({ message: 'Request updated' });
  });
});

app.listen(3001, () => {
  console.log('Server running on http://localhost:3001');
});