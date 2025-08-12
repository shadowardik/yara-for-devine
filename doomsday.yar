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
        $1 = "k.class" nocase ascii 
        $2 = "m.class" nocase ascii 
        $3 = "r.class" nocase ascii 
        $4 = "s.class" nocase ascii 
        
    condition:
        all of them
}
