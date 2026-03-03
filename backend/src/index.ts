import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';

import authRouter from './routes/auth';
import workspacesRouter from './routes/workspaces';
import prisma from './lib/prisma';
import positionsRouter from './routes/positions';
import candidatesRouter from './routes/candidates';
import filesRouter from './routes/files';
import analyticsRouter from './routes/analytics';

const app = express();
const PORT = process.env.PORT ?? 3001;

// ─── Security headers ─────────────────────────────────────────────────────────
// contentSecurityPolicy disabled: DEMO.html uses a large inline <script> block
// which helmet's default CSP (script-src 'self') would silently block.
app.use(helmet({ contentSecurityPolicy: false }));

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production'
      ? (process.env.FRONTEND_URL ?? 'http://localhost:5173')
      : true, // allow any origin in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ─── Rate limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // stricter limit for auth endpoints
  message: { error: 'Too many auth attempts, please try again later' },
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// ─── Body parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Serve DEMO.html at root ──────────────────────────────────────────────────
// Local dev:  dist/index.js → ../DEMO.html = backend/DEMO.html
// Docker:     /app/dist/index.js → ../DEMO.html = /app/DEMO.html
app.get('/', (_req, res) => {
  res.sendFile(path.resolve(__dirname, '../DEMO.html'));
});

// ─── Pre-auth: peek at invite details (no JWT required) ───────────────────────
// Used by the frontend to show "You've been invited by X to workspace Y" before login.
app.get('/api/invite-info', async (req, res) => {
  const { token } = req.query;
  if (!token || typeof token !== 'string') {
    res.status(400).json({ error: 'token is required' });
    return;
  }
  const invite = await prisma.invitation.findUnique({
    where: { token },
    include: {
      workspace: { select: { name: true } },
      invitedBy:  { select: { name: true } },
    },
  });
  if (!invite) { res.status(404).json({ error: 'Invitation not found' }); return; }
  if (invite.acceptedAt) { res.status(400).json({ error: 'Invitation already accepted' }); return; }
  if (invite.expiresAt < new Date()) { res.status(400).json({ error: 'Invitation has expired' }); return; }
  res.json({ workspaceName: invite.workspace.name, inviterName: invite.invitedBy.name, role: invite.role, email: invite.email });
});

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth', authRouter);
app.use('/api/workspaces', workspacesRouter);

// Positions nested under workspaces
app.use('/api/workspaces/:workspaceId/positions', positionsRouter);

// Candidates nested under positions
app.use('/api/positions/:positionId/candidates', candidatesRouter);

// Files — standalone (candidateId + columnId passed in body)
app.use('/api/files', filesRouter);

// Analytics
app.use('/api/workspaces/:workspaceId/analytics', analyticsRouter);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[ERROR]', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Prevent unhandled promise rejections from crashing the server ────────────
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ API running on http://localhost:${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV ?? 'development'}`);
});

export default app;
