import "math"

rule nixploitCC {
    meta:
        author = "qwersome"
        description = "super mega puper zyper detection for nixplot.cc"
        date = "2025-07-31"

    strings:
        $a = "VirtualProtect" nocase
        $b = "GetProcAddress" nocase
        $c = "!wwwwwww" nocase

    condition:
        $a and $b and $c and
        math.entropy(0, filesize) > 7 and
        math.entropy(0, filesize) < 7.5
}
