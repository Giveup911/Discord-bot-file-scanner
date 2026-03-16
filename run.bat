@echo off
cd /d "%~dp0"

if "%~1"=="" (
    echo Running batch analysis on PUT_JAR_HERE...
    echo.
    java -cp tools JarAnalyzer --batch PUT_JAR_HERE
) else if "%~1"=="--scan" (
    echo Scanning system for infections...
    echo.
    java -cp tools JarAnalyzer --scan
) else (
    java -cp tools JarAnalyzer %*
)

echo.
pause
