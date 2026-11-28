// Prototype pollution from browser input. Each line marked FLAG gives exactly one finding.

const settings = {};

// Nested write with keys from the query string.
export function applyQuery() {
  const params = new URLSearchParams(window.location.search);
  const section = params.get('section');
  const key = params.get('key');
  settings[section] = settings[section] || {};
  settings[section][key] = params.get('value'); // FLAG
}

// Keys split out of the hash.
export function applyHash(store) {
  const [group, name, value] = location.hash.slice(1).split('/');
  // eslint-disable-next-line @typescript-eslint/no-unused-expressions -- the lazy-init idiom under test
  store[group] || (store[group] = {});
  store[group][name] = decodeURIComponent(value); // FLAG
}

// Lazy init through an alias of the first level.
export function cacheFromHash(cache) {
  const [ns, id] = decodeURIComponent(location.hash.substring(1)).split(':');
  const bucket = cache[ns] || (cache[ns] = {});
  bucket[id] = Date.now(); // FLAG
}

// Keys read from a JSON payload in the URL.
export function applyState(config) {
  const state = JSON.parse(decodeURIComponent(location.hash.slice(1)));
  config[state.section][state.key] = state.value; // FLAG
}

// Keys from a postMessage payload.
window.addEventListener('message', (event) => {
  const { path, prop, val } = event.data;
  settings[path][prop] = val; // FLAG
});

// The handler registered by name.
function onMessage(e) {
  const msg = JSON.parse(e.data);
  settings[msg.a][msg.b] = msg.c; // FLAG
}
window.addEventListener('message', onMessage);

// Inline getters in the brackets.
export function inline() {
  const q = new URL(document.URL).searchParams;
  settings[q.get('s')][q.get('k')] = 1; // FLAG
}

// Recursive merge called with browser input.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {}; // FLAG
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
const defaults = { theme: { color: 'blue' } };
merge(defaults, JSON.parse(new URLSearchParams(location.search).get('opts')));

// Top-level module code.
const top = new URLSearchParams(location.search);
const t1 = top.get('a');
const t2 = top.get('b');
settings[t1][t2] = true; // FLAG
