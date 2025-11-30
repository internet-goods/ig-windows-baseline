echo google gemini save current wmic persistence listeners to a file using a bat script not powershell
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
set "OutputFilePath=c:\Windows\Temp\ig-windows-baseline\wmic\%COMPUTERNAME%-wmi_listeners_data-%CurrentDate%.txt"

echo Exporting WMI Persistence Listeners to %OutputFilePath%

echo ---------------------------------------------------- >> %OutputFilePath%
echo WMI Event Filters (^__EventFilter) >> %OutputFilePath%
echo ---------------------------------------------------- >> %OutputFilePath%
wmic /namespace:"\\root\subscription" path __EventFilter get /format:list >> %OutputFilePath% 2>&1

echo. >> %OutputFilePath%
echo ---------------------------------------------------- >> %OutputFilePath%
echo WMI Event Consumers (^__EventConsumer) >> %OutputFilePath%
echo ---------------------------------------------------- >> %OutputFilePath%
wmic /namespace:"\\root\subscription" path __EventConsumer get /format:list >> %OutputFilePath% 2>&1

echo. >> %OutputFilePath%
echo ---------------------------------------------------- >> %OutputFilePath%
echo WMI Filter to Consumer Bindings (^__FilterToConsumerBinding) >> %OutputFilePath%
echo ---------------------------------------------------- >> %OutputFilePath%
wmic /namespace:"\\root\subscription" path __FilterToConsumerBinding get /format:list >> %OutputFilePath% 2>&1

echo. >> %OutputFilePath%
echo Export complete. Data saved to %OutputFilePath%
