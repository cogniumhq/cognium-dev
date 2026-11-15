// CWE-1336 fixture: request values used as the source of a server-side
// template. Every line marked FLAG must give exactly one `template_injection`
// finding.
import express, { type Request, type Response } from 'express';
import ejs from 'ejs';
import Handlebars from 'handlebars';
import handlebars from 'handlebars';
import pug from 'pug';
import nunjucks from 'nunjucks';

const app = express();

export function previewEjs(req: Request, res: Response) {
  res.send(ejs.render(req.body.template, { site: 'docs' })); // FLAG
}

export function previewHandlebars(req: Request, res: Response) {
  const source = req.query.tpl as string;
  const render = Handlebars.compile(source); // FLAG
  res.send(render({ site: 'docs' }));
}

export function previewHandlebarsLower(req: Request, res: Response) {
  const layout = req.body.layout;
  res.send(handlebars.compile(layout)({})); // FLAG
}

export function previewPug(req: Request, res: Response) {
  res.send(pug.render(req.body.source)); // FLAG
}

export function previewNunjucks(req: Request, res: Response) {
  const { body } = req.body;
  res.send(nunjucks.renderString(body, { site: 'docs' })); // FLAG
}

export function bannerEjs(req: Request, res: Response) {
  const title = req.query.title as string;
  res.send(ejs.render(`<h1>${title}</h1>`, {})); // FLAG
}

app.post('/preview/ejs', previewEjs);
app.get('/preview/hbs', previewHandlebars);
app.post('/preview/hbs2', previewHandlebarsLower);
app.post('/preview/pug', previewPug);
app.post('/preview/njk', previewNunjucks);
app.get('/banner', bannerEjs);
