@echo off
REM Comprehensive v1.7 Test Script
echo.
echo ========================================
echo Mikmbr v1.7.0 - Comprehensive Testing
echo ========================================
echo.

echo [1/8] Checking Python version...
py --version
echo.

echo [2/8] Testing CLI basic functionality...
py -m mikmbr.cli scan test_v17_features.py
echo.

echo [3/8] Testing --fail-on critical (should exit 0)...
py -m mikmbr.cli scan test_v17_features.py --fail-on critical
if %errorlevel%==0 (echo ✓ PASS: Correctly exits 0) else (echo ✗ FAIL: Expected exit 0)
echo.

echo [4/8] Testing --fail-on medium (should exit 1)...
py -m mikmbr.cli scan test_v17_features.py --fail-on medium
if %errorlevel%==1 (echo ✓ PASS: Correctly exits 1) else (echo ✗ FAIL: Expected exit 1)
echo.

echo [5/8] Testing --context 3...
py -m mikmbr.cli scan test_v17_features.py --context 3
echo.

echo [6/8] Testing JSON format...
py -m mikmbr.cli scan test_v17_features.py --format json >nul 2>&1
if %errorlevel%==1 (echo ✓ PASS: JSON format works) else (echo ✗ FAIL: JSON format issue)
echo.

echo [7/8] Testing SARIF format...
py -m mikmbr.cli scan test_v17_features.py --format sarif >nul 2>&1
if %errorlevel%==1 (echo ✓ PASS: SARIF format works) else (echo ✗ FAIL: SARIF format issue)
echo.

echo [8/8] Running unit tests...
py -m pytest tests/test_exit_codes.py tests/test_context_lines.py -v
echo.

echo ========================================
echo Testing Complete!
echo ========================================
echo.
echo To run validation demo: py validate_v17.py
echo.
pause
