# Python Command Note

## Current Setup

Your system uses `py` launcher instead of `python` command.

All batch files and scripts have been updated to use:
- `py` instead of `python`
- `py -m pytest` instead of `python -m pytest`
- `py -m mikmbr.cli` instead of `python -m mikmbr.cli`

## Files Updated
- ✅ `test_v17.bat` - Uses `py`
- ✅ `run_tests.bat` - Uses `py`
- ✅ `validate_v17.py` - Uses `py`

## Why `py` Instead of `python`?

The `py` launcher is Python's official Windows launcher. It:
- Works even when `python` isn't in PATH
- Automatically finds your Python installation
- Is the recommended way to run Python on Windows

## Commands That Now Work

```bash
# Run tests
test_v17.bat

# Run validation
py validate_v17.py

# Run CLI
py -m mikmbr.cli scan test_v17_features.py --context 3

# Run pytest
py -m pytest tests/ -v
```

## If You Want to Use `python` Command

To make `python` command work:
1. Windows Settings → "Manage app execution aliases"
2. Turn OFF "python.exe" and "python3.exe"
3. Restart Command Prompt

But `py` works fine and is actually the recommended approach on Windows!
