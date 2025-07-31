import "math"

rule troxill_client {
    meta:
        author = "qwersome"
        description = "my first yara rule for devine"
        date = "2025-07-31"

    strings:
        $a = "GetProcAddress" nocase
        $b = "D3D11CreateDeviceAndSwapChain" nocase

    condition:
        $a and $b and 
        math.entropy(0, filesize) > 7.5 and
        math.entropy(0, filesize) < 8 and
        filesize >= 13 * 1024 * 1024 and 
        filesize <= 23 * 1024 * 1024
}