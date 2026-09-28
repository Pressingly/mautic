// mPass SSO gateway-rejection reload (sso-rules-moneta tasks 5.27 part 2, G13b).
// Loads the real 1.core.js in a vm with a chainable jQuery stub. Run: node --test app/bundles/CoreBundle/Tests/js/mpassReload.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../Assets/js/1.core.js', import.meta.url), 'utf8');

function load(ssoEnabled, { online = true } = {}) {
    const handlers = [];
    const storage = new Map();
    let reloads = 0;
    const listeners = {};

    // Any property access or call returns the stub again, except .ajaxError, which is recorded.
    const stub = new Proxy(function () {}, {
        get: (_, prop) => (prop === 'ajaxError' ? (fn) => { handlers.push(fn); return stub; } : stub),
        apply: () => stub,
    });

    const window = {
        sessionStorage: { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v) },
        location: { reload: () => { reloads += 1; }, pathname: '/s/dashboard' },
        addEventListener: (type, fn) => { listeners[type] = fn; },
        navigator: { onLine: online },
    };
    const context = { jQuery: stub, window, document: {}, navigator: {}, mauticMpassSso: ssoEnabled, Date, setTimeout: () => {} };
    vm.createContext(context);
    try {
        vm.runInContext(source, context);
    } catch {
        // Later top-level code may trip over the stub; the handler under test is registered first.
    }

    return {
        handlers,
        fire: (status, statusText = 'error', crossDomain = false) =>
            handlers.forEach((h) => h({}, { status, statusText }, { crossDomain })),
        reloads: () => reloads,
        unload: () => listeners.beforeunload(),
        shouldReload: context.MauticVars.mpassShouldReload,
    };
}

test('401 from the gateway reloads the tab exactly once within 30 s', () => {
    const tab = load(true);
    assert.equal(tab.handlers.length, 1);
    tab.fire(401);
    tab.fire(401);
    assert.equal(tab.reloads(), 1);
});

test('status 0 (off-origin redirect) reloads, an aborted request does not', () => {
    const aborted = load(true);
    aborted.fire(0, 'abort');
    assert.equal(aborted.reloads(), 0);

    const redirected = load(true);
    redirected.fire(0, 'error');
    assert.equal(redirected.reloads(), 1);
});

test('a timeout or a request cancelled by navigation never reloads', () => {
    const timedOut = load(true);
    timedOut.fire(0, 'timeout');
    assert.equal(timedOut.reloads(), 0);

    const navigating = load(true);
    navigating.unload();
    navigating.fire(0, 'error');
    navigating.fire(401);
    assert.equal(navigating.reloads(), 0);
});

test('403 is a permission denial and never reloads', () => {
    const tab = load(true);
    tab.fire(403);
    tab.fire(500);
    assert.equal(tab.reloads(), 0);
});

test('no handler when SSO is off', () => {
    assert.equal(load(false).handlers.length, 0);
});

test('the 30 s loop guard', () => {
    const { shouldReload } = load(true);
    assert.equal(shouldReload(401, 'error', 100000, 80000), false);
    assert.equal(shouldReload(401, 'error', 110000, 80000), true);
    assert.equal(shouldReload(401, 'error', 110000, 0), true);
});

test('a cross-origin request never reloads (the gateway only fronts this origin)', () => {
    const tab = load(true);
    tab.fire(401, 'error', true);
    tab.fire(0, 'error', true);
    assert.equal(tab.reloads(), 0);
});

test('an offline browser never reloads', () => {
    const tab = load(true, { online: false });
    tab.fire(0, 'error');
    tab.fire(401);
    assert.equal(tab.reloads(), 0);
});
