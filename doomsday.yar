rule doomsday_client {
    meta:
        author = "qwersome"
        description = "yar for doomsday client"
        date = "2025-08-12"

    strings:
        $a = "f.class" nocase ascii 
        $b = "g.class" nocase ascii 
        $c = "h.class" nocase ascii 
        $d = "i.class" nocase ascii 
        $f = "k.class" nocase ascii 
        $g = "y.class" nocase ascii 
        $h = "m.class" nocase ascii 
        $i = "r.class" nocase ascii 
        $j = "s.class" nocase ascii 
        $k = "t.class" nocase ascii 
        
    condition:
        all of them
}
