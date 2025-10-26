import express from 'express';
import session from 'express-session';
import keycloakConnect from 'keycloak-connect';
import dotenv from 'dotenv';
dotenv.config();

const KeycloakLib = keycloakConnect.default ?? keycloakConnect;

const app = express();
const PORT = process.env.PORT || 3000;

const memoryStore = new session.MemoryStore();

app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

// Keycloak config (programmatic). Container uses 'keycloak' host from compose network.
const keycloakConfig = {
  realm: process.env.KC_REALM || 'ZeroTrustLab',
  'auth-server-url': `http://${process.env.KC_HOST || 'keycloak'}:${process.env.KC_PORT || 8080}/auth`,
  'ssl-required': 'external',
  resource: process.env.KC_CLIENT || 'dummy-api',
  'bearer-only': true,
  'confidential-port': 0
};

// initialize Keycloak object (this will not crash if Keycloak server/realm not ready immediately)
let keycloak;
try {
  keycloak = new KeycloakLib({ store: memoryStore }, keycloakConfig);
} catch (err) {
  console.error('Failed to initialize keycloak-connect library:', err);
  // fallback: set dummy object that rejects protects (so server keeps running)
  keycloak = {
    middleware: () => (req, res, next) => next(),
    protect: () => (req, res, next) => {
      res.status(401).send('Auth not configured yet');
    }
  };
}

app.use(keycloak.middleware());

// simple audit/log middleware (Zero Trust: log every request)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} from ${req.ip}`);
  next();
});

// Public endpoint
app.get('/', (req, res) => res.send('Welcome to Zero Trust Dummy API!'));

// Protected routes
app.get('/user', keycloak.protect('realm:user'), (req, res) => {
  res.send('Hello, user! You have basic access.');
});

app.get('/admin', keycloak.protect('realm:admin'), (req, res) => {
  res.send('Welcome admin! You have privileged access.');
});

// health
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => console.log(`Dummy API running on port ${PORT}`));
