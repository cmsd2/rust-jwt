#!/bin/sh

MSG="eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
SIG="cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

.\target\debug\jwktool.exe sign -j 'samples\jws\a2 - rs256\4-rsa-key.json' -m $MSG
.\target\debug\jwktool.exe verify -j 'samples\jws\a2 - rs256\4-rsa-key.json' -m $MSG -s $SIG

.\target\debug\jwktool.exe convert -j 'samples\jws\a2 - rs256\4-rsa-key.json' -f pem --out private.pem
.\target\debug\jwktool.exe convert -j 'samples\jws\a2 - rs256\4-rsa-key.json' -f pem --pubout --out public.pem
