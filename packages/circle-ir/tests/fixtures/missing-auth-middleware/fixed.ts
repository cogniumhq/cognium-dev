// CWE-862 fixture: the same routes as vulnerable.ts with the authentication
// middleware added. Must produce no `missing-auth-middleware` finding.
import { Router, type Request, type Response, type NextFunction } from 'express';
import passport from 'passport';

declare const notes: { find(id: string): unknown; remove(id: string): void; update(id: string, v: unknown): void };
declare function requireAuth(req: Request, res: Response, next: NextFunction): void;

export const notesRouter = Router();

notesRouter.get('/notes/:id', requireAuth, (req: Request, res: Response) => {
  res.json(notes.find(req.params.id));
});

notesRouter.post('/notes', requireAuth, (req: Request, res: Response) => {
  res.status(201).json(req.body);
});

notesRouter.delete('/notes/:id', requireAuth, (req: Request, res: Response) => {
  notes.remove(req.params.id);
  res.sendStatus(204);
});

notesRouter.put('/notes/:id', requireAuth, updateNote);

function updateNote(req: Request, res: Response) {
  notes.update(req.params.id, req.body);
  res.sendStatus(204);
}

export const accountsRouter = Router();

accountsRouter.get('/api/v1/accounts/:accountId', passport.authenticate('jwt', { session: false }), (req: Request, res: Response) => {
  res.json({ id: req.params.accountId });
});

accountsRouter.patch('/api/v1/accounts/:accountId', passport.authenticate('jwt', { session: false }), (req: Request, res: Response) => {
  res.json({ id: req.params.accountId, ...req.body });
});
