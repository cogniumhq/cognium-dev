// CWE-1336 fixture: the same handlers as vulnerable.ts with a fixed template
// and the request value passed as data. Must produce no `template_injection`
// finding.
import express, { type Request, type Response } from 'express';
import ejs from 'ejs';
import Handlebars from 'handlebars';
import handlebars from 'handlebars';
import pug from 'pug';
import nunjucks from 'nunjucks';

const app = express();

export function previewEjs(req: Request, res: Response) {
  res.send(ejs.render('<main><%= template %></main>', { template: req.body.template }));
}

export function previewHandlebars(req: Request, res: Response) {
  const source = req.query.tpl as string;
  const render = Handlebars.compile('<pre>{{source}}</pre>');
  res.send(render({ source }));
}

export function previewHandlebarsLower(req: Request, res: Response) {
  const layout = req.body.layout;
  res.send(handlebars.compile("<div class=\"layout\">{{layout}}</div>")({ layout }));
}

export function previewPug(req: Request, res: Response) {
  res.send(pug.render('pre= source', { source: req.body.source }));
}

export function previewNunjucks(req: Request, res: Response) {
  const { body } = req.body;
  res.send(nunjucks.renderString('<pre>{{ body }}</pre>', { body }));
}

export function bannerEjs(req: Request, res: Response) {
  const title = req.query.title as string;
  res.send(ejs.render(`<h1><%= title %></h1>`, { title }));
}

app.post('/preview/ejs', previewEjs);
app.get('/preview/hbs', previewHandlebars);
app.post('/preview/hbs2', previewHandlebarsLower);
app.post('/preview/pug', previewPug);
app.post('/preview/njk', previewNunjucks);
app.get('/banner', bannerEjs);
