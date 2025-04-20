# Contributing to Flowlyt

Thank you for your interest in contributing to Flowlyt! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Setting Up the Development Environment](#setting-up-the-development-environment)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
- [Code Style and Guidelines](#code-style-and-guidelines)
  - [Go Code Guidelines](#go-code-guidelines)
  - [Testing](#testing)
- [Project Structure](#project-structure)
- [Adding New Features](#adding-new-features)
  - [Adding New Detection Rules](#adding-new-detection-rules)
  - [Adding New Policy Types](#adding-new-policy-types)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Prerequisites

To contribute to Flowlyt, you'll need:

- Go 1.16 or higher
- Git
- A GitHub account

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/flowlyt.git
   cd flowlyt
   ```
3. Add the original repository as an upstream remote:
   ```bash
   git remote add upstream https://github.com/harekrishnarai/flowlyt.git
   ```
4. Install dependencies:
   ```bash
   go mod download
   ```
5. Build the project:
   ```bash
   go build -o flowlyt.exe ./cmd/flowlyt
   ```

## Development Workflow

### Branching Strategy

- `main` - Main branch that reflects the production state
- `develop` - Development branch where features are integrated before release
- Feature branches - Create from `develop` with format `feature/feature-name`
- Bugfix branches - Create from `develop` with format `bugfix/bug-description`
- Hotfix branches - Create from `main` with format `hotfix/fix-description`

### Commit Messages

Follow these guidelines for commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line
- Consider starting the commit message with an applicable emoji:
  - ✨ `:sparkles:` for new features
  - 🐛 `:bug:` for bug fixes
  - 📚 `:books:` for documentation
  - ♻️ `:recycle:` for refactoring
  - 🧪 `:test_tube:` for adding tests
  - 🚀 `:rocket:` for performance improvements

### Pull Requests

1. Create a new branch from `develop` (or `main` for hotfixes)
2. Make your changes
3. Add or update tests as necessary
4. Update documentation as necessary
5. Ensure all tests pass
6. Push your branch to your fork
7. Submit a pull request to the original repository

## Code Style and Guidelines

### Go Code Guidelines

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` or `goimports` to format your code
- Document all exported functions, types, and constants
- Keep functions small and focused on a single responsibility

### Testing

- Write tests for all new functionality
- Make sure all tests pass before submitting a PR
- Use the existing test structure for guidance

## Project Structure

```
flowlyt/
├── cmd/                     # Command-line applications
│   └── flowlyt/             # Main command-line application
├── pkg/                     # Reusable packages
│   ├── common/              # Common types and utilities
│   ├── github/              # GitHub API integration
│   ├── parser/              # Workflow file parsing
│   ├── policies/            # Policy engine
│   ├── report/              # Report generation
│   ├── rules/               # Security rule definitions
│   ├── secrets/             # Secret detection logic
│   └── shell/               # Shell script analysis
└── test/                    # Test fixtures and integration tests
    ├── policies/            # Test policies
    └── sample-repo/         # Sample repository for testing
```

## Adding New Features

### Adding New Detection Rules

To add a new security rule to Flowlyt:

1. Identify the category your rule belongs to
2. Add the rule to the appropriate file in the `pkg/rules` directory
3. Write tests for your rule in the corresponding test file
4. Update documentation to describe the new rule

### Adding New Policy Types

To add a new policy type:

1. Add the policy logic to the `pkg/policies` directory
2. Create example/template policies in the `test/policies` directory
3. Write tests to validate the policy functionality
4. Update documentation to describe the new policy type

## Reporting Bugs

When reporting bugs, please include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots (if applicable)
- System information (OS, Go version, etc.)
- Any additional context that might be helpful

## Feature Requests

When submitting feature requests:

- Describe the feature you'd like to see
- Explain why this feature would be useful
- Provide examples of how this feature would work
- Consider including mockups or wireframes if it's a UI feature

## Documentation

Good documentation is crucial. When making changes, please:

- Update README.md if necessary
- Update or add documentation in code comments
- Consider adding examples to help users understand your changes

## License

By contributing to Flowlyt, you agree that your contributions will be licensed under the project's [license](LICENSE).