@ECHO This script gets you started building PCLCrypto.

@WHERE GIT > nul 2> nul
@IF ERRORLEVEL 1 GOTO NOGIT

@PAUSE

@SET NUGET="%~dp0src\.nuget\nuget.exe"

pushd "%~dp0"
git submodule init
git submodule update
pushd PCLTesting
%nuget% restore
cd build
msbuild
popd
pushd src
%nuget% restore
msbuild
popd
popd

@GOTO END

:NOGIT
@ECHO FAILURE: could not find git. Please make sure it is on your system PATH.
@EXIT /b 1

:END
