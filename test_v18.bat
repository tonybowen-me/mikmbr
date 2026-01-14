@echo off
echo ========================================
echo Mikmbr v1.8 Dependency Scanning Tests
echo ========================================
echo.

echo [1/3] Running Unit Tests...
echo ----------------------------------------
py -m pytest tests/test_dependency_scanning.py -v
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: Some unit tests failed
    echo.
)

echo.
echo.
echo [2/3] Running Integration Tests...
echo ----------------------------------------
py -m pytest tests/test_dependency_scanning.py::TestDependencyScannerIntegration -v
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: Integration tests failed
    echo.
)

echo.
echo.
echo [3/3] Running Validation Script...
echo ----------------------------------------
py validate_v18.py

echo.
echo ========================================
echo Test Suite Complete
echo ========================================
pause
