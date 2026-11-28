// Browser input written into objects safely. No finding.

const settings = {};

// Guard on the prototype keys.
export function guarded() {
  const params = new URLSearchParams(window.location.search);
  const section = params.get('section');
  const key = params.get('key');
  if (section === '__proto__' || section === 'constructor' || section === 'prototype') return;
  settings[section] = settings[section] || {};
  settings[section][key] = params.get('value');
}

// Null-prototype root.
const registry = Object.create(null);
export function nullProto() {
  const [group, name] = location.hash.slice(1).split('/');
  registry[group] = registry[group] || Object.create(null);
  registry[group][name] = true;
}

// A Map instead of an object.
const byGroup = new Map();
export function map() {
  const [group, name] = location.hash.slice(1).split('/');
  if (!byGroup.has(group)) byGroup.set(group, new Map());
  byGroup.get(group).set(name, true);
}

// Only keys the object already owns.
export function own() {
  const params = new URLSearchParams(location.search);
  const section = params.get('s');
  if (!Object.hasOwn(settings, section)) return;
  settings[section][params.get('k')] = params.get('v');
}

// Keys from a constant allow-list.
const SECTIONS = ['theme', 'layout'];
export function allowList() {
  const params = new URLSearchParams(location.search);
  const section = params.get('s');
  if (!SECTIONS.includes(section)) return;
  settings[section][params.get('k')] = params.get('v');
}

// The first key is a lookup in a constant table.
const TABLE = { a: 'theme', b: 'layout' };
export function table() {
  const params = new URLSearchParams(location.search);
  settings[TABLE[params.get('s')]][params.get('k')] = 1;
}

// One key only.
export function oneKey() {
  const params = new URLSearchParams(location.search);
  settings.theme[params.get('k')] = params.get('v');
}

// Keys that are not browser input.
export function constants(items) {
  for (const item of items) settings[item.group][item.name] = item.value;
}

// A key passed through a checking function.
export function checked() {
  const params = new URLSearchParams(location.search);
  const a = toSafeKey(params.get('a'));
  const b = params.get('b');
  settings[a][b] = 1;
}

// Guarded recursive merge, called with browser input.
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else target[key] = source[key];
  }
}
safeMerge(settings, JSON.parse(location.hash.slice(1)));

// A postMessage payload written one level deep.
window.addEventListener('message', (event) => {
  settings[event.data.key] = event.data.value;
});

// A click handler's event is not a message.
document.addEventListener('click', (event) => {
  const { a, b } = event.data || {};
  settings[a][b] = 1;
});

// A WebSocket's message event carries the app's own server data.
const socket = new WebSocket('wss://example.com/feed');
socket.addEventListener('message', (event) => {
  const { group, id, value } = JSON.parse(event.data);
  settings[group][id] = value;
});
