import { Router, type Request, type Response, type NextFunction } from 'express';

declare const notes: { find(id: string): unknown; remove(id: string): void; update(id: string, v: unknown): void };
declare function requireAuth(req: Request, res: Response, next: NextFunction): void;

export const notesRouter = Router();

notesRouter.get('/notes/:id', requireAuth, (req: Request, res: Response) => {
  res.json(notes.find(req.params.id));
});

notesRouter.delete('/notes/:id', requireAuth, (req: Request, res: Response) => {
  notes.remove(req.params.id);
  res.sendStatus(204);
});

notesRouter.patch('/notes/:id', (req: Request, res: Response) => {
  notes.update(req.params.id, req.body);
  res.sendStatus(204);
});
