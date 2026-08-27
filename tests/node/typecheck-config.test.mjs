import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

test('TypeScript strict typecheck is configured for extensions', () => {
  const tsconfig = readJson('tsconfig.json');
  assert.equal(tsconfig.compilerOptions.strict, true);
  assert.equal(tsconfig.compilerOptions.noEmit, true);
  assert.equal(tsconfig.compilerOptions.moduleResolution, 'NodeNext');
  assert.ok(tsconfig.include.includes('.pi/extensions/**/*.ts'));

  const pkg = readJson('package.json');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.devDependencies.typescript, '5.9.3');
  assert.equal(pkg.scripts.typecheck, 'tsc --noEmit');

  const testHarness = readFileSync('bin/test', 'utf8');
  assert.match(testHarness, /node_modules\/\.bin\/tsc --noEmit/);
});
