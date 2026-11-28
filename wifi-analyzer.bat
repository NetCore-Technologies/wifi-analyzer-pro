@echo off
setlocal
set "ROOT_DIR=%~dp0"
if not defined PYTHON set "PYTHON=py -3"
set "PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%"
%PYTHON% -m wifi_analyzer_backend.cli %*
exit /b %ERRORLEVEL%
