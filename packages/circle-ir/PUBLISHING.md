# Publishing Guide

This document outlines the process for publishing circle-ir to npm.

## Prerequisites

1. **npm Account**: Ensure you have an npm account with publish access to the `circle-ir` package
2. **npm Token**: Generate an npm automation token and add it as `NPM_TOKEN` secret in GitHub repository settings
3. **Repository Access**: Write access to the GitHub repository for pushing tags

## Phase 3: CI/CD Setup (Completed)

The following GitHub Actions workflows are configured:

### CI Workflow (`.github/workflows/ci.yml`)
- Triggers on: Push to `main` and all pull requests
- Tests on Node.js: 18.x, 20.x, 22.x
- Runs:
  - Type checking (`npm run typecheck`)
  - Full build (`npm run build:all`)
  - Tests with coverage (`npm run test:coverage`)
  - Coverage threshold verification (≥75%)

### Publish Workflow (`.github/workflows/publish.yml`)
- Triggers on: Version tags matching `v*` (e.g., `v3.8.2`)
- Runs on Node.js 20.x
- Steps:
  1. Verifies tag version matches `package.json` version
  2. Runs full test suite
  3. Builds all targets (Node.js, browser, core)
  4. Publishes to npm with provenance
  5. Creates GitHub release with auto-generated notes

## Phase 4: Manual Publishing Steps

### One-Time Setup

1. **Configure npm Token in GitHub**:
   ```bash
   # Generate token at https://www.npmjs.com/settings/[username]/tokens
   # Go to GitHub repo → Settings → Secrets and variables → Actions
   # Add new secret: NPM_TOKEN
   ```

2. **Verify npm credentials locally** (optional):
   ```bash
   npm login
   npm whoami  # Should show your npm username
   ```

### Publishing a New Version

1. **Ensure clean working directory**:
   ```bash
   git status  # Should show no uncommitted changes
   ```

2. **Run full verification locally**:
   ```bash
   npm install
   npm run build:all
   npm test
   npm run test:coverage
   ```

3. **Update version** (if needed):
   ```bash
   # For patch releases (3.8.2 → 3.8.3)
   npm version patch

   # For minor releases (3.8.2 → 3.9.0)
   npm version minor

   # For major releases (3.8.2 → 4.0.0)
   npm version major

   # Or manually edit package.json and commit
   ```

4. **Push version tag to trigger automated publish**:
   ```bash
   git push origin main
   git push origin v3.8.2  # Use actual version number
   ```

5. **Monitor GitHub Actions**:
   - Go to: https://github.com/cogniumhq/circle-ir/actions
   - Watch the "Publish to npm" workflow
   - Verify successful completion

6. **Verify npm publication**:
   ```bash
   npm view circle-ir version  # Should show new version
   npm info circle-ir  # Full package info
   ```

### Alternative: Manual Publish (Not Recommended)

If you need to publish manually without GitHub Actions:

```bash
npm install
npm run build:all
npm test
npm publish  # prepublishOnly hook runs build:all and test automatically
```

**Note**: Automated publishing via GitHub Actions is preferred as it:
- Ensures consistent build environment
- Provides npm provenance for supply chain security
- Creates GitHub releases automatically
- Prevents accidental publishes from dirty working directories

## Version Strategy

- **Patch** (x.y.Z): Bug fixes, minor improvements, security patches
- **Minor** (x.Y.0): New features, backward-compatible changes
- **Major** (X.0.0): Breaking changes, major refactors

## Post-Publication Checklist

- [ ] Verify package appears on https://www.npmjs.com/package/circle-ir
- [ ] Test installation: `npm install circle-ir@latest`
- [ ] Verify all entry points work (main, core, browser)
- [ ] Update CHANGELOG.md with release notes
- [ ] Announce release (if significant)

## Troubleshooting

### Publish workflow fails with "version mismatch"
- Ensure the git tag version (e.g., `v3.8.2`) matches `package.json` version (e.g., `3.8.2`)

### Publish workflow fails with "authentication failed"
- Verify `NPM_TOKEN` secret is set in GitHub repository settings
- Ensure npm token has publish permissions and hasn't expired

### Coverage check fails
- Run `npm run test:coverage` locally
- Coverage must be ≥75% for all metrics (statements, branches, functions, lines)
- See `vitest.config.ts` for threshold configuration

### Build fails in CI but works locally
- Check Node.js version (CI uses 18.x, 20.x, 22.x)
- Ensure all dependencies are in `package.json`, not globally installed
- Clear local cache: `rm -rf node_modules package-lock.json && npm install`
