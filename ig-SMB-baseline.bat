:: SMB Hardening Script
:: Targets: Disabling SMBv1, Enabling SMB Signing, and Restricting Null Sessions.

echo Starting SMB Hardening...

:: 1. Disable SMBv1 Protocol (The "WannaCry" fix)
:: This disables the SMBv1 Server component.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

:: 2. Require SMB Digitally Signed Communications (Always)
:: This prevents Man-in-the-Middle (MitM) relay attacks.
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireMessageSigning" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "enablesecuritysignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d 1 /f

:: 3. Disable Null Session Pipes and Shares
:: Prevents anonymous users from enumerating shares or IPC information.
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f

:: 4. Enable SMB Encryption (SMB 3.0+)
:: Forces encryption for all data in transit across the server.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EncryptData" /t REG_DWORD /d 1 /f

:: 5. Disable Insecure Guest Logons
reg add "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 0 /f

echo SMB Hardening Complete. A reboot is required for all changes to take effect.
echo Disabling NTLMv1 and enforcing NTLMv2...

:: 1. Set LMCompatibilityLevel to 5
:: 0: Send LM & NTLM
:: 1: Send LM & NTLM (use NTLMv2 if negotiated)
:: 2: Send NTLM only
:: 3: Send NTLMv2 only
:: 4: Send NTLMv2 only (refuse LM)
:: 5: Send NTLMv2 only (refuse LM & NTLMv1)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LMCompatibilityLevel" /t REG_DWORD /d 5 /f

:: 2. Restrict NTLM: Outgoing traffic to remote servers
:: Forces the client to use NTLMv2 for all outgoing requests.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NtlmMinClientSec" /t REG_DWORD /d 536870912 /f

:: 3. Restrict NTLM: Incoming traffic
:: Forces the server to require NTLMv2 for incoming requests.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NtlmMinServerSec" /t REG_DWORD /d 536870912 /f

echo NTLMv1 has been disabled. A reboot is recommended.
