# Contributing to circle-ir

Thank you for your interest in contributing to circle-ir! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/cogniumhq/circle-ir.git
   cd circle-ir
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Run tests**
   ```bash
   npm test
   ```

4. **Build the project**
   ```bash
   npm run build:all
   ```

## Development Guidelines

### Code Quality

- **TypeScript**: All code must be written in TypeScript with strict mode enabled
- **No `any` types**: Avoid using `any` without explicit justification
- **Test coverage**: Maintain ≥75% unit test coverage for new code
- **Universal core**: Core library code must be environment-agnostic (no Node.js-specific APIs)

### Testing

```bash
npm test              # Run all tests
npm run test:watch    # Run tests in watch mode
npm run test:coverage # Run with coverage report
```

### Building

```bash
npm run build         # Compile TypeScript
npm run build:browser # Bundle for browser
npm run build:core    # Bundle core library
npm run build:all     # All builds
npm run typecheck     # Type check only
```

## Pull Request Process

1. **Fork the repository** and create your branch from `main`
2. **Write tests** for any new functionality
3. **Update documentation** if you're changing APIs or adding features
4. **Run the test suite** and ensure all tests pass
5. **Verify coverage** if your changes affect analysis accuracy:
   ```bash
   npm run test:coverage
   ```
6. **Submit a pull request** with a clear description of your changes

## Project Structure

```
src/
├── core/           # Parser and IR generation (Tree-sitter)
├── analysis/       # Taint analysis engine
├── languages/      # Language plugins (Java, JS, Python, Go, Rust, Bash, HTML)
├── resolution/     # Cross-file resolution and type hierarchy
├── types/          # TypeScript type definitions
├── utils/          # Logging utilities
├── core-lib.ts     # Core library entry point
├── browser.ts      # Browser entry point
└── index.ts        # Main entry point

configs/
├── sources/        # Taint source definitions (YAML/JSON)
└── sinks/          # Taint sink definitions (YAML/JSON)

docs/
├── SPEC.md         # Circle-IR specification
└── ARCHITECTURE.md # System architecture
```

## Adding New Vulnerability Patterns

See [CLAUDE.md](CLAUDE.md#common-tasks) for detailed instructions on:
- Adding new taint sources
- Adding new taint sinks
- Adding language support

Brief summary:
1. Add source patterns to `configs/sources/*.yaml`
2. Add sink patterns to `configs/sinks/*.yaml`
3. Write tests to verify detection
4. Run benchmarks to ensure no regressions

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Include relevant code samples when possible

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build better security tools together.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
