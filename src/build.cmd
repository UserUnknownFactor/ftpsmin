IF NOT DEFINED IS_ENV_READY (
    SET IS_ENV_READY=1
    CALL "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"
)
rem openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
nmake