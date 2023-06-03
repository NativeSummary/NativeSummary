
call .\gradlew.bat buildExtension
if %errorlevel% neq 0 exit /b %errorlevel%

echo Install to "%userprofile%\.ghidra\.ghidra_10.1.2_PUBLIC\Extensions\native_summary_bai"
rmdir /s /q "%userprofile%\.ghidra\.ghidra_10.1.2_PUBLIC\Extensions\native_summary_bai"

pushd dist
for /f "tokens=*" %%a in ('dir /b /od') do set newest=%%a
"C:\Program Files\7-Zip\7z.exe" x "%newest%" -o%userprofile%\.ghidra\.ghidra_10.1.2_PUBLIC\Extensions -y
popd
if %errorlevel% neq 0 exit /b %errorlevel%
