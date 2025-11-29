# Portable Scanner Tests

This directory contains unit tests for the portable scanner bypass analyzers and other components.

## Running Tests

Run all tests:
```bash
python -m unittest discover tests -v
```

Run specific test file:
```bash
python -m unittest tests/test_bypass_helpers.py -v
python -m unittest tests/test_bypass_scanner.py -v
```

## Test Coverage

### test_bypass_helpers.py
- Tests for helper functions used by the bypass analyzer:
  - `contains_homoglyphs()`: Unicode homoglyph detection
  - `is_spoofed_signature()`: File signature vs extension mismatch detection

### test_bypass_scanner.py
- Comprehensive tests for the BypassAnalyzerScanner:
  - Homoglyph pattern detection
  - File signature analysis
  - Obfuscated class pattern matching
  - Scanner configuration and initialization
  - Escalation logic for multiple technique detections

## Adding New Tests

When adding new bypass detection techniques, ensure:
1. Add unit tests for any new helper functions
2. Test edge cases (empty files, missing files, permission errors)
3. Test pattern matching with both positive and negative cases
4. Verify graceful degradation on errors
