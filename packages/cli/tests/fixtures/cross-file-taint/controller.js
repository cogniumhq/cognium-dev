import { run } from './helper';

export function handle(req) {
  let a = req.query.x;
  let b = a;
  run(b);
}
