// CWE-862 near miss: a router-level guard; the file is skipped.
import { Router, type Request, type Response, type NextFunction } from 'express';

declare function requireAuth(req: Request, res: Response, next: NextFunction): void;

export const r = Router();
r.get('/public/:id', (req: Request, res: Response) => { res.json({ id: req.params.id }); });
r.use(requireAuth);
r.get('/items/:id', requireAuth, (req: Request, res: Response) => { res.json({ id: req.params.id }); });
r.delete('/items/:id', (req: Request, res: Response) => { res.json({ id: req.params.id }); });
