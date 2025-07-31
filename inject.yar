import "math"

rule possible_injection {
    meta:
        author = "qwersome"
        description = "detect injections"
        date = "2025-08-01"

   strings:
	    $s1 = "WriteProcessMemory" nocase ascii wide
	    $s2 = "CreateRemoteThread" nocase ascii wide
      $s3 = "CharUpperBuffW" fullword ascii
      $s4 = "GetProcAddress" fullword ascii
      $s5 = "LoadLibraryA" fullword ascii
      $s6 = "GetVersion" fullword ascii
      $s8 = "InternetOpenUrlA" fullword ascii 
	    $s9 = "VirtualProtectEx" nocase ascii wide
	    $s10 = "EnumProcesses" nocase ascii wide
	    $s11 = "EnumProcessModules" nocase ascii wide
	    $s13 = "GetThreadContext" nocase ascii wide
	    $s14 = "MapViewOfFile" nocase ascii wide
	    $s15 = "SuspendThread" nocase ascii wide
	    $s16 = "VirtualAllocEx" nocase ascii wide
   condition:
      uint16(0) == 0x5a4d and
      2 of ($s*)
}
