mkdir Get-ProcessMitigation
Get-ProcessMitigation -System > Get-ProcessMitigation/Get-ProcessMitigation-System-$(Get-Date -Format 'yyy-mm-dd-HH-MM').txt
Get-ProcessMitigation > Get-ProcessMitigation/Get-ProcessMitigation-$(Get-Date -Format 'yyy-mm-dd-HH-MM').txt
