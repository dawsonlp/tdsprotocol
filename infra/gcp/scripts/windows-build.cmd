@echo off
set "TDS_VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
rem The first campaign's bootstrap lost quoting around --installPath.
rem Reuse those installed tools; future bootstraps use the canonical path.
if not exist "%TDS_VCVARS%" set "TDS_VCVARS=C:\Program\VC\Auxiliary\Build\vcvars64.bat"
call "%TDS_VCVARS%" >nul
if errorlevel 1 exit /b %errorlevel%
cd /d C:\tds\source\clients\rust
if "%~1"=="test" goto tests
if "%~1"=="clippy" goto clippy
"%USERPROFILE%\.cargo\bin\cargo.exe" build --all-features --example login_probe --locked
exit /b %errorlevel%
:tests
"%USERPROFILE%\.cargo\bin\cargo.exe" test --all-features --locked
exit /b %errorlevel%
:clippy
"%USERPROFILE%\.cargo\bin\cargo.exe" clippy --workspace --all-features --all-targets --locked -- -D warnings
