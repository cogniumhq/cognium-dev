// CWE-862 near misses: must produce no `missing-auth-middleware` finding.
import { Router, type Request, type Response, type NextFunction } from 'express';

declare function requireAuth(req: Request, res: Response, next: NextFunction): void;
declare function requireAdmin(req: Request, res: Response, next: NextFunction): void;
declare function loadOwnedPost(req: Request, res: Response, next: NextFunction): void;
declare const posts: { remove(id: string): void; update(id: string, v: unknown): void };

// Public reads beside guarded writes: GET routes are not considered.
export const products = Router();
products.post('/products', requireAuth, (req: Request, res: Response) => { res.json(req.body); });
products.get('/products/:id', (req: Request, res: Response) => { res.json({ id: req.params.id }); });

// The route carries a middleware the rule does not know: it may be the guard.
export const postsRouter = Router();
postsRouter.get('/posts/:id', requireAuth, (req: Request, res: Response) => { res.json({ id: req.params.id }); });
postsRouter.delete('/posts/:id', loadOwnedPost, (req: Request, res: Response) => { posts.remove(req.params.id); res.end(); });

// The handler checks the caller itself.
postsRouter.put('/posts/:id', (req: Request, res: Response) => {
  if (!req.user) return res.sendStatus(401);
  posts.update(req.params.id, req.body);
  return res.end();
});

// The sibling has only a role guard (login may be mounted by the parent app).
export const users = Router();
users.delete('/users/:id', requireAdmin, (req: Request, res: Response) => { res.json({ id: req.params.id }); });
users.patch('/users/:id', (req: Request, res: Response) => { res.json({ id: req.params.id }); });

// A different resource on the same router.
export const misc = Router();
misc.get('/settings/:key', requireAuth, (req: Request, res: Response) => { res.json({ key: req.params.key }); });
misc.post('/webhooks/:source', (req: Request, res: Response) => { res.json({ source: req.params.source }); });

// A route without a path parameter.
misc.post('/settings', (req: Request, res: Response) => { res.json(req.body); });

// Guarded by a middleware array.
misc.delete('/settings/:key', [requireAuth], (req: Request, res: Response) => { res.json({ key: req.params.key }); });
