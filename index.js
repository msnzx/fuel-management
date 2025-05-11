import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import Datastore from 'nedb';
import util from 'util';
util.isDate   = util.types.isDate;
util.isRegExp = util.types.isRegExp;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ensure ./db folder exists
const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);

// load NeDB files
const usersDB = new Datastore({ filename: path.join(dbDir, 'users.db'), autoload: true });

// 1) enforce unique usernames
usersDB.ensureIndex({ fieldName: 'username', unique: true }, err => {
  if (err) console.error('Failed to set unique index on username:', err);
});

const fuelDB  = new Datastore({ filename: path.join(dbDir, 'fuel_logs.db'), autoload: true });

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({ secret: 'mysecret', resave: false, saveUninitialized: false }));
app.use(express.static(path.join(__dirname, 'public')));

function ensureAuth(req, res, next) {
  req.session.user ? next() : res.redirect('/login');
}

function redirectIfLoggedIn(req, res, next) {
  req.session.user ? res.redirect('/dashboard') : next();
}

// page routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/register', redirectIfLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/login', redirectIfLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/dashboard', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html')));
app.get('/new-log', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/new-log.html')));
app.get('/edit-log', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/edit-log.html')));
app.get('/stats', ensureAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/stats.html')));
app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

// 2) registration handler
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Username and password are both required.');
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    usersDB.insert({ username, password: hash }, (err, newUser) => {
      if (err) {
        console.error('DB insert error:', err);
        // check for unique‐index violation
        if (err.errorType === 'uniqueViolated') {
          return res.send('That username is already taken.');
        }
        return res.send('Database error—please check server logs.');
      }
      console.log('Registered new user:', newUser.username);
      res.redirect('/login');
    });
  } catch (e) {
    console.error('Hashing or unexpected error:', e);
    res.send('Server error—see console.');
  }
});

// login handler (unchanged)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Username & password are required.');
  }

  usersDB.findOne({ username }, async (err, user) => {
    if (err) {
      console.error('DB find error:', err);
      return res.send('Database error.');
    }
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send('Invalid credentials.');
    }
    req.session.user = user.username;
    res.redirect('/dashboard');
  });
});

// 8) Fuel-log REST API (example)
app.get('/api/fuel-logs', ensureAuth, (req, res) =>
  fuelDB.find({ username: req.session.user }, (e, docs) => res.json(docs))
);

app.post('/api/fuel-logs', ensureAuth, (req, res) => {
  const { carName, amount, pricePerUnit, mileage, datetime } = req.body;
  fuelDB.insert({
    username: req.session.user,
    carName,
    amount: parseFloat(amount),
    pricePerUnit: parseFloat(pricePerUnit),
    mileage: parseFloat(mileage),
    datetime
  }, (err, doc) => err ? res.status(500).send('Insert error') : res.json(doc));
});

// Update a fuel log
app.put('/api/fuel-logs/:id', ensureAuth, (req, res) => {
  const { carName, amount, pricePerUnit, mileage, datetime } = req.body;
  fuelDB.update(
    { _id: req.params.id, username: req.session.user }, 
    { $set: {
      carName,
      amount: parseFloat(amount),
      pricePerUnit: parseFloat(pricePerUnit),
      mileage: parseFloat(mileage),
      datetime
    }}, 
    {}, 
    (err, numReplaced) => {
      if (err) return res.status(500).send('Update error');
      if (numReplaced === 0) return res.status(404).send('Log not found or not authorized');
      res.json({ success: true });
    }
  );
});

// Delete a fuel log
app.delete('/api/fuel-logs/:id', ensureAuth, (req, res) => {
  fuelDB.remove(
    { _id: req.params.id, username: req.session.user }, 
    {}, 
    (err, numRemoved) => {
      if (err) return res.status(500).send('Delete error');
      if (numRemoved === 0) return res.status(404).send('Log not found or not authorized');
      res.json({ success: true });
    }
  );
});

// 9) Stats endpoint
app.get('/api/stats', ensureAuth, (req, res) => {
  fuelDB.find({ username: req.session.user }).sort({ datetime: 1 }).exec((err, logs) => {
    if (err) return res.status(500).send('DB error');
    if (logs.length < 2) return res.json({ efficiency: 0, costPerMile: 0 });

    const dist = logs[logs.length-1].mileage - logs[0].mileage;
    const totalFuel = logs.reduce((s, l) => s + l.amount, 0);
    const totalCost = logs.reduce((s, l) => s + l.amount * l.pricePerUnit, 0);

    res.json({
      efficiency: (dist/totalFuel).toFixed(2),
      costPerMile: (totalCost/dist).toFixed(2)
    });
  });
});

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
