# Changelog - Version 1.0.2

**Release Date:** December 5, 2025

## 🎉 What's New

Version 1.0.2 adds enhanced secret detection and improves SARIF output for better GitHub Security integration.

## ✨ Features

### Enhanced Secret Detection
- Added support for detecting AWS, GCP, and Azure credentials
- Improved entropy-based detection algorithm
- Reduced false positives for common patterns

### SARIF Output Improvements
- Better severity mapping for GitHub Security tab
- Enhanced help text for findings
- Improved remediation guidance

## 🐛 Bug Fixes

- Fixed issue with remote repository cloning (#12)
- Corrected line number mapping in SARIF reports
- Fixed panic when scanning empty workflow files

## 🔧 Improvements

- Faster scanning for large organizations
- Better error messages for common issues
- Enhanced progress indicators

## 📝 Notes

This release improves the GitHub Actions integration and makes it easier to identify and fix security issues directly in the GitHub Security tab.
