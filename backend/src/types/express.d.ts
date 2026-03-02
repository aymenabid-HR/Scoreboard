// Augment Express's Request type so route handlers that use req.userId
// are compatible with the standard RequestHandler signature.
declare global {
  namespace Express {
    interface Request {
      userId: string;
      memberRole?: string;
      resolvedWorkspaceId?: string;
    }
  }
}

export {};
