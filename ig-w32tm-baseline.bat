echo For non-domain joined computers, set time to time.google.com
w32tm /config /manualpeerlist:time.google.com /syncfromflags:manual /reliable:yes /update
