@echo off
rem ===========================================================================
rem  Gateway-GO build script (Windows entry, 2026-10-24)
rem
rem  Produces a deploy-ready set under dist\<goos>-<goarch>\ :
rem      s5a3-gateway.exe / s5a3-admin.exe / wwwroot\
rem
rem  NOTE: wwwroot MUST ship with the binaries. The admin UI is served by
rem        http.FileServer(http.Dir("wwwroot")) -- read from disk, NOT go:embed
rem        (only static/register.html is embedded). Rebuilding the binary does
rem        NOT update the admin pages. On 2026-10-24 only the binaries were
rem        copied to the server, so the admin console kept showing the old UI.
rem
rem  This file is intentionally ASCII-only: cmd.exe parses .bat as the OEM
rem  codepage (GBK on zh-CN), and non-ASCII comments corrupt variable
rem  assignments mid-script.
rem
rem  Usage: build.bat                 default linux amd64
rem         build.bat linux arm64
rem         build.bat windows amd64
rem ===========================================================================
setlocal EnableExtensions DisableDelayedExpansion

if not defined GO_EXE set "GO_EXE=go"
if "%~1"=="" (set "GOOS=linux") else (set "GOOS=%~1")
if "%~2"=="" (set "GOARCH=amd64") else (set "GOARCH=%~2")

if not "%GOOS%"=="linux" if not "%GOOS%"=="windows" if not "%GOOS%"=="darwin" (
  echo Unsupported GOOS: %GOOS% 1>&2
  exit /b 2
)
if not "%GOARCH%"=="amd64" if not "%GOARCH%"=="arm64" (
  echo Unsupported GOARCH: %GOARCH% 1>&2
  exit /b 2
)

set "CGO_ENABLED=0"
set "EXT="
if "%GOOS%"=="windows" set "EXT=.exe"
set "OUT=%~dp0dist\%GOOS%-%GOARCH%"

echo Building Gateway-GO -^> %GOOS%/%GOARCH%
if not exist "%OUT%" mkdir "%OUT%"
if errorlevel 1 exit /b 1

pushd "%~dp0"

"%GO_EXE%" build -buildvcs=false -mod=readonly -trimpath -o "%OUT%\s5a3-gateway%EXT%" ./cmd/gateway
if errorlevel 1 goto failed
echo   [1/3] s5a3-gateway%EXT%

"%GO_EXE%" build -buildvcs=false -mod=readonly -trimpath -o "%OUT%\s5a3-admin%EXT%" ./cmd/admin
if errorlevel 1 goto failed
echo   [2/3] s5a3-admin%EXT%

if exist "wwwroot" (
  if exist "%OUT%\wwwroot" rmdir /s /q "%OUT%\wwwroot"
  xcopy "wwwroot" "%OUT%\wwwroot\" /E /I /Y >nul
  if errorlevel 1 goto failed
  echo   [3/3] wwwroot\
) else (
  echo   [3/3] WARNING: wwwroot not found - admin pages will 404 1>&2
)

popd
echo.
echo Build succeeded: %OUT%
dir /b "%OUT%"
echo.
echo Deploy: copy gateway + admin + wwwroot together into the server directory.
echo         Binary only without wwwroot = admin UI stays on the old version.
exit /b 0

:failed
popd
echo Build FAILED 1>&2
exit /b 1
