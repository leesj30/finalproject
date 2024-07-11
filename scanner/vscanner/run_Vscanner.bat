@echo off
set /p url="Enter the URL to scan: "
set /p depth="Enter the depth (default is 3): "
if "%depth%"=="" set depth=3
python main.py %url% --depth %depth%
pause
