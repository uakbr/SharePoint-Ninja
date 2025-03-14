# Contributing to SharePoint Restricted Environment Data Collector

Thank you for your interest in contributing to the SharePoint Restricted Environment Data Collector project! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct which expects all contributors to:
- Be respectful and inclusive
- Focus on constructive feedback
- Maintain professionalism in communications

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:
1. Check if the issue already exists in the Issues section
2. Use the issue template to create a new issue if needed
3. Provide as much detail as possible, including steps to reproduce for bugs

### Submitting Changes

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Follow the coding standards (see below)
4. Write or update tests as necessary
5. Submit a pull request with a clear description of the changes

### Pull Request Process

1. Update the README.md or documentation with details of changes if appropriate
2. Update the CHANGELOG.md with details of changes
3. The PR will be merged once it has been reviewed and approved

## Coding Standards

### PowerShell Guidelines

- Follow PowerShell best practices and style guidelines
- Use meaningful variable and function names
- Include parameter types and validation
- Add comment-based help for all functions
- Avoid hardcoding values; use configuration files instead

### File Organization

- Place modules in the `src/modules/` directory
- Place configuration templates in the `src/config/` directory
- Place tests in the `tests/` directory

### Error Handling

- Implement proper error handling with try/catch blocks
- Log all errors with appropriate detail
- Use the Failsafe module for retries and fallbacks

## Testing

- Write tests for all new functionality
- Ensure all tests pass before submitting a PR
- Test against multiple SharePoint environments when possible

## Documentation

- Update documentation for any changed functionality
- Document all functions with comment-based help
- Maintain the CHANGELOG.md with all notable changes

Thank you for contributing to make the SharePoint Restricted Environment Data Collector better! 