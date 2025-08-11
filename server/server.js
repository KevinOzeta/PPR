require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:5500',
  credentials: true,
}));

const PORT = process.env.PORT || 4000;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = 'session';

// Limpiamos espacios y eliminamos vacíos en ALLOWED_ORIGINS
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map(origin => origin.trim())
  .filter(origin => origin.length > 0);

app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

const client = new OAuth2Client(CLIENT_ID);
const usersFile = path.join(__dirname, 'allowedUsers.json');

function readAllowedUsers() {
  if (!fs.existsSync(usersFile)) return [];
  return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}

function findUserByEmail(email) {
  const users = readAllowedUsers();
  return users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
}

// Endpoint que recibe el id_token desde el frontend
app.post('/api/auth/google', async (req, res) => {
  const { id_token } = req.body;
  if (!id_token) return res.status(400).json({ ok: false, message: 'id_token missing' });

  try {
    const ticket = await client.verifyIdToken({ idToken: id_token, audience: CLIENT_ID });
    const payload = ticket.getPayload();

    if (!payload.email_verified) return res.status(403).json({ ok: false, message: 'Email no verificado por Google' });

    const userEntry = findUserByEmail(payload.email);
    if (!userEntry) return res.status(403).json({ ok: false, message: 'Usuario no autorizado' });

    const role = userEntry.role || 'sistematizador';
    const tokenPayload = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      role
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });

    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000
    });

    res.json({ ok: true, role, name: tokenPayload.name });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ ok: false, message: 'Token inválido' });
  }
});

// Middleware para proteger rutas
function authMiddleware(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ ok: false, message: 'No autenticado' });
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ ok: false, message: 'Token inválido' });
    req.user = payload;
    next();
  });
}

// Middleware para roles
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ ok: false, message: 'No autenticado' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ ok: false, message: 'Acceso denegado' });
    next();
  };
}

// Endpoint para que el frontend consulte la sesión actual
app.get('/api/me', authMiddleware, (req, res) => {
  const { sub, email, name, picture, role } = req.user;
  res.json({ ok: true, user: { id: sub, email, name, picture, role } });
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true });
  res.json({ ok: true });
});

// Endpoint protegido solo para coordinadores o admin
app.get('/api/protected/coordinacion', authMiddleware, requireRole('coordinador', 'admin'), (req, res) => {
  res.json({ ok: true, secret: 'Datos sensibles de coordinación' });
});

app.listen(PORT, () => console.log(`Server corriendo en http://localhost:${PORT}`));
