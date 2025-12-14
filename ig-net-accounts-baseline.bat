ECHO STIG HARDENING USING NET ACCOUNTS CMD
#Windows account lockout duration must be configured to 15 minutes or greater.</title>
net accounts /lockoutduration:30
#The number of allowed bad logon attempts must be configured to three or less.</title>
net accounts /lockoutthreshold:3
#The period of time before the bad logon counter is reset must be configured to 15 minutes.</title>
net accounts /lockoutwindow:15
#The password history must be configured to 24 passwords remembered.</title>
net accounts /uniquepw:24
#The maximum password age must be configured to 60 days or less.</title>
#so annoyingnet accounts /maxpwage:60
#The minimum password age must be configured to at least 1 day.</title>
net accounts /minpwage:1
#Passwords must, at a minimum, be 14 characters.</title>
net accounts /minpwlen:14
