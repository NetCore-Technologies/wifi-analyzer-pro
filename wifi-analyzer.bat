@echo off
setlocal
set "ROOT_DIR=%~dp0"
if not defined PYTHON set "PYTHON=py -3"
if defined PYTHONPATH (
  set "PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%ROOT_DIR%"
)
%PYTHON% -m wifi_analyzer_backend.cli %*
exit /b %ERRORLEVEL%
