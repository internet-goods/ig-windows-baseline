reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client /v Enabled /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server /v Enabled /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client /v Enabled /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server /v Enabled /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client /v Enabled /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server /v Enabled /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\\Protocols\TLS 1.2\Server /v DisabledByDefault /t REG_DWORD /d 0 /f
echo https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_enabling_turnoffcheck.yml
reg add HKLM\Policies\Microsoft\Windows\ScriptedDiagnostics /v TurnOffCheck /t REG_DWORD /d 0
echo 32b runkey
echo https://github.com/SigmaHQ/sigma/blob/0597250ee1008d2354e457cb9eff3a8490457cd2/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml#L29
echo 64b runkey
#REMhttps://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.yml

