@echo off
start /b python server.py
timeout /t 2 /nobreak > nul
start python client.py
start python client.py
echo Messenger started. Close this window to keep server running in background.
pause
