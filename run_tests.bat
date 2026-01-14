@echo off
REM Batch file to run v1.7 tests
REM Run this from Command Prompt or PowerShell

echo ========================================
echo Running v1.7 Test Suite
echo ========================================
echo.

echo Testing exit code logic...
python -m pytest tests/test_exit_codes.py -v
echo.

echo Testing context lines...
python -m pytest tests/test_context_lines.py -v
echo.

echo ========================================
echo Running validation script...
echo ========================================
python validate_v17.py

pause
