import "math"

rule nixploitCC {
    meta:
        author = "qwersome"
        description = "super mega puper zyper detection for nixplot.cc"
        date = "2025-07-31"

    strings:
        $a = "++\\map\\x64\\Release.pdb" nocase
        $b = "VirtualProtect" nocase
        $c = "GetProcAddress" nocase

    condition:
        $a and $b and $c and
        math.entropy(0, filesize) > 7 and
        math.entropy(0, filesize) < 7.2
}
