@echo off
setlocal EnableExtensions
title Aegis Updater

REM Always operate from the folder this script lives in, regardless of which
REM drive/directory the user double-clicked from (/d switches drive too).
cd /d "%~dp0"

echo ============================================================
echo   Aegis Updater
echo   %CD%
echo ============================================================
echo.

REM ---- Preflight -----------------------------------------------------------

where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] git was not found on PATH.
    echo         Install Git for Windows: https://git-scm.com/download/win
    goto :fail
)

git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
    echo [ERROR] This folder is not a git repository, so there is nothing
    echo         to pull updates into. Clone the repo first.
    goto :fail
)

REM ---- Step 1: pull latest code ---------------------------------------------

echo [1/3] Pulling latest code...
git pull --ff-only
if errorlevel 1 (
    echo.
    echo [ERROR] git pull failed. Most common causes:
    echo   - You have local edits. Stash them, update, then re-apply:
    echo       git stash
    echo       update.bat
    echo       git stash pop
    echo   - No network connection to the remote.
    goto :fail
)
echo.

REM ---- Step 2: make sure the virtual environment exists ---------------------

echo [2/3] Checking virtual environment...
if not exist "venv\Scripts\python.exe" (
    echo   venv not found -- creating one...
    py -3 -m venv venv 2>nul || python -m venv venv
    if not exist "venv\Scripts\python.exe" (
        echo [ERROR] Could not create a venv. Is Python installed and on PATH?
        goto :fail
    )
)
call "venv\Scripts\activate.bat"
echo   Using:
python -c "import sys; print('   ' + sys.executable)"
echo.

REM ---- Step 3: install/update dependencies -----------------------------------

echo [3/3] Installing/updating dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements-windows.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Dependency install failed -- scroll up for the pip error.
    echo         Note: if only pywintrace failed, Aegis still runs using the
    echo         WMI polling fallback (higher latency).
    goto :fail
)

echo.
echo ============================================================
echo   Update complete. You are on:
git log -1 --format="   %%h  %%s"
echo ============================================================
echo.

REM ---- Optional: launch Aegis elevated (ETW needs Administrator) -------------

choice /c YN /m "Launch Aegis now (opens an Administrator window for ETW)"
if errorlevel 2 goto :done

REM %~dp0 ends with a backslash; append a dot so the escaped closing quote
REM isn't swallowed as \" by PowerShell's argument parsing.
powershell -NoProfile -Command "Start-Process cmd -Verb RunAs -ArgumentList '/k cd /d \"%~dp0.\" && call venv\Scripts\activate.bat && python main.py'"

:done
echo.
echo Done. You can close this window.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
