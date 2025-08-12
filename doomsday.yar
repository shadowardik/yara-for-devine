rule doomsday_client {
    meta:
        author = "qwersome"
        description = "yar for doomsday client"
        date = "2025-08-12"

    strings:
        $a = "f.class" fullword ascii 
        $b = "g.class" fullword ascii 
        $c = "h.class" fullword ascii 
        $d = "i.class" fullword ascii 
        $f = "k.class" fullword ascii 
        $g = "y.class" fullword ascii 
        $h = "m.class" fullword ascii 
        $i = "r.class" fullword ascii 
        $j = "s.class" fullword ascii 
        $k = "t.class" fullword ascii 
        
    condition:
        all of them
}
