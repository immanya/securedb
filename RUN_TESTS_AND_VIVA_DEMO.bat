@echo off
title SecureDB Tests and Viva Demonstration
color 0B

echo ======================================================================
echo           SecureDB - Automated Test Suite and Viva Demo
echo ======================================================================
echo.
echo [1/2] Running Complete Pytest Suite (24 Tests)...
echo.
python -m pytest -v
echo.
echo ======================================================================
echo [2/2] Running Standalone Cryptographic Bit-Flip Tamper Demonstration...
echo ======================================================================
echo.
python scripts/demo_tamper.py
echo.
echo ======================================================================
echo Verification Complete. Press any key to exit.
echo ======================================================================
pause
