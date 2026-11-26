@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel%==0 (
    python -m windscribe_finder %*
    set "EXIT_CODE=%errorlevel%"
    goto :done
)

where py >nul 2>&1
if %errorlevel%==0 (
    py -3 -m windscribe_finder %*
    set "EXIT_CODE=%errorlevel%"
    goto :done
)

echo Error: Python 3 is not found on PATH. Please install Python 3.13+ and try again.
set "EXIT_CODE=1"

:done
if "%~1"=="" pause
exit /b %EXIT_CODE%
