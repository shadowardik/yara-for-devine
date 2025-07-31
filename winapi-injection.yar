              rule win_api_injection {
	strings:
		$api0 = "OpenProcess" nocase ascii wide
		$api1 = "VirtualAllocEx" nocase ascii wide
		$api2 = "WriteProcessMemory" nocase ascii wide
		$api3 = "CreateRemoteThread" nocase ascii wide
		$api4 = "SendNotifyMessage" nocase ascii wide
		$api5 = "SuspendThread" nocase ascii wide
		$api6 = "SetThreadContext" nocase ascii wide
		$api7 = "ResumeThread" nocase ascii wide
		$api8 = "NtQueueApcThread" nocase ascii wide
		$api9 = "VirtualProtectEx" nocase ascii wide
		$api10 = "GetModuleHandle" nocase ascii wide
		$api11 = "AdjustTokenPrivileges" nocase ascii wide
		$api12 = "EnumProcesses" nocase ascii wide
		$api13 = "EnumProcessModules" nocase ascii wide
		$api14 = "GetThreadContext" nocase ascii wide
		$api15 = "MapViewOfFile" nocase ascii wide
		$api16 = "Module32First" nocase ascii wide
		$api17 = "Module32Next" nocase ascii wide
		$api18 = "Process32First" nocase ascii wide
		$api19 = "Process32Next" nocase ascii wide
		$api20 = "CreateToolhelp32Snapshot" nocase ascii wide
		$api21 = "Thread32First" nocase ascii wide
		$api22 = "Thread32Next" nocase ascii wide
		$api23 = "GetEIP" nocase ascii wide
	condition:
	   2 of ($api*)
}
