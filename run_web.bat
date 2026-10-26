@echo off
chcp 65001 > nul
echo ========================================================
echo  KHOI CHAY TRANG WEB MAT MA HOC: AES, RSA, SHA-256
echo ========================================================
echo Dang khoi dong may chu web tren http://localhost:8080 ...
start "" "http://localhost:8080/index.html"
python server.py
if errorlevel 1 (
    echo Python khong co san, dang mo truc tiep index.html tren trinh duyet...
    start "" "index.html"
)
pause
