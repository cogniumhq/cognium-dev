/**
 * A small sample of the table inputs `runHtmlIndex` takes, written for these tests: enough ARIA 1.2
 * roles and ARIA-in-HTML rows to exercise the algorithms. It is not a complete catalog — a caller
 * passes its own, and none ships with the package.
 */
import type { AriaViews, HtmlAriaViews } from '../../src/html-index.js';

const INPUT_ROWS: [string, string][] = [
  ['button', 'button'], ['checkbox', 'checkbox'], ['radio', 'radio'], ['reset', 'button'], ['submit', 'button'],
  ['image', 'button'], ['email', 'textbox'], ['number', 'spinbutton'], ['range', 'slider'],
];

export const html: HtmlAriaViews = {
  'row-match': [
    { key: 'a[href]', tag: 'a', all: [{ has: 'href' }] },
    { key: 'a:not([href])', tag: 'a', all: [{ lacks: 'href' }] },
    { key: 'area[href]', tag: 'area', all: [{ has: 'href' }] },
    { key: 'area:not([href])', tag: 'area', all: [{ lacks: 'href' }] },
    { key: 'img[alt=""]', tag: 'img', all: [{ eq: ['alt', ''] }, { lacks: 'aria-label' }, { lacks: 'aria-labelledby' }, { lacks: 'title' }] },
    { key: 'img', tag: 'img', all: [{ 'any-of': [{ 'nonempty-attr': 'alt' }, { has: 'aria-label' }, { has: 'aria-labelledby' }, { has: 'title' }] }] },
    { key: 'button', tag: 'button', all: [{ 'not-first-child-of': 'select' }] },
    { key: 'div', tag: 'div', all: [{ 'parent-not': 'dl' }] },
    { key: 'input[list]', tag: 'input', all: [{ has: 'list' }, { 'type-in-or-default': ['text', 'search', 'tel', 'url', 'email'] }] },
    ...INPUT_ROWS.map(([type]) => ({ key: `input[type=${type}]`, tag: 'input', all: [{ eq: ['type', type] }] })),
    { key: 'input[type=text]', tag: 'input', all: [{ 'type-in-or-default': ['text'] }, { lacks: 'list' }] },
    { key: 'select[multiple]', tag: 'select', all: [{ 'any-of': [{ has: 'multiple' }, { gt: ['size', 1] }] }] },
    { key: 'select', tag: 'select', all: [{ lacks: 'multiple' }, { 'not-gt': ['size', 1] }] },
  ],
  'tag-row': {
    body: 'body', dialog: 'dialog', footer: 'footer', h1: 'heading', h2: 'heading', h3: 'heading', header: 'header', html: 'html', li: 'li', main: 'main', nav: 'nav',
    ol: 'ol', option: 'option', p: 'p', span: 'span', table: 'table', td: 'td', textarea: 'textarea', th: 'th', tr: 'tr', ul: 'ul',
  },
  'implicit-role-by-row': {
    'a[href]': 'link', 'a:not([href])': 'generic', 'area[href]': 'link', 'area:not([href])': 'generic', 'img[alt=""]': 'none', img: 'img',
    button: 'button', div: 'generic', 'input[list]': 'combobox', 'input[type=text]': 'textbox', 'select[multiple]': 'listbox', select: 'combobox',
    ...Object.fromEntries(INPUT_ROWS.map(([type, role]) => [`input[type=${type}]`, role])),
    body: 'generic', dialog: 'dialog', footer: 'contentinfo', header: 'banner', heading: 'heading', html: 'generic', li: 'listitem', main: 'main', nav: 'navigation', ol: 'list',
    option: 'option', p: 'paragraph', span: 'generic', table: 'table', td: 'cell', textarea: 'textbox', th: 'columnheader', tr: 'row', ul: 'list',
  },
  'implicit-role-by-tag-default': { a: 'link', area: 'link', button: 'button', div: 'generic', img: 'img', input: 'button', select: 'combobox' },
};

export const aria: AriaViews = {
  'role-names': [
    'alert', 'banner', 'button', 'cell', 'checkbox', 'columnheader', 'combobox', 'contentinfo', 'dialog', 'generic', 'group', 'heading', 'img', 'link', 'list',
    'listbox', 'listitem', 'main', 'navigation', 'none', 'option', 'paragraph', 'presentation', 'radio', 'row', 'rowgroup', 'slider',
    'spinbutton', 'tab', 'table', 'tablist', 'tabpanel', 'textbox',
  ],
  'global-attributes': [
    'aria-atomic', 'aria-busy', 'aria-controls', 'aria-current', 'aria-describedby', 'aria-details', 'aria-disabled', 'aria-dropeffect',
    'aria-errormessage', 'aria-flowto', 'aria-grabbed', 'aria-haspopup', 'aria-hidden', 'aria-invalid', 'aria-keyshortcuts', 'aria-label',
    'aria-labelledby', 'aria-live', 'aria-owns', 'aria-relevant', 'aria-roledescription',
  ],
  'name-from-contents': ['button', 'cell', 'checkbox', 'columnheader', 'heading', 'link', 'option', 'radio', 'row', 'tab'],
  'required-owned': {
    list: ['listitem'], listbox: ['option'], row: ['cell', 'columnheader'], rowgroup: ['row'], table: ['row', 'rowgroup'], tablist: ['tab'],
  },
};

export const views = { html, aria };
