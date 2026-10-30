@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto install
py -3 -m venv .venv
if errorlevel 1 goto failed
:install
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m streamlit run app.py --server.address 127.0.0.1 --server.maxUploadSize 20 --browser.gatherUsageStats false
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Setup or startup failed. Check the error above.
echo Install Python 3.11 or newer from python.org with the Python launcher enabled.
pause
exit /b 1
