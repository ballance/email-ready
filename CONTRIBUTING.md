# Contributing to Email Ready

First off, thank you for considering contributing to Email Ready! It's people like you that make Email Ready such a great tool for businesses worldwide.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please be respectful and professional in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples** (domain names, if not sensitive)
* **Describe the behavior you observed and expected**
* **Include your Python version and OS**
* **Include any error messages in full**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the suggested enhancement**
* **Provide specific examples to demonstrate the enhancement**
* **Describe the current behavior and expected behavior**
* **Explain why this enhancement would be useful**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure your code follows the existing style
4. Make sure your code passes basic quality checks
5. Issue that pull request!

## Development Process

1. **Maintain backward compatibility** - Changes should not break existing usage
2. **Keep both versions in sync** - Features should work in both check.py and check_secure.py where appropriate
3. **Document changes** - Update README and other docs as needed
4. **Security first** - Any changes must maintain or improve security
5. **User experience** - Keep the business version jargon-free

## Style Guidelines

### Python Style

* Follow PEP 8
* Use meaningful variable names
* Add docstrings to all functions
* Keep functions under 50 lines
* Use type hints where helpful

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters
* Reference issues and pull requests liberally after the first line

### Documentation

* Use clear, simple language in documentation
* Include examples where possible
* Keep README updated with any new features
* Update CHANGELOG.md for notable changes

## Testing

Before submitting a pull request:

1. Test both versions with real domains
2. Test with invalid input
3. Test with domains that have various configurations
4. Ensure rate limiting still works in secure version
5. Verify error messages are helpful

## Questions?

Feel free to open an issue for any questions about contributing!

## Recognition

Contributors will be recognized in the CHANGELOG.md file. Thank you for helping make email configuration easier for businesses everywhere!