def euclidePGCD(a,b):
    while b != 0:
        r = a % b
        a = b
        b = r
    return a


def euclideEtendu(a, b):
    r1 = a 
    r2 = b
    u1 = 1
    v1 = 0
    u2 = 0
    v2 = 1
    while r > 0:
        q = r1 // r2
        r3 = r1 
        u3 = u1 
        v3 = v1
        r1 = r2 
        u1 = u2 
        v1 = v2
        r2 = r3 - q*r2 
        u2 = u3 - q*u2 
        v2 = v3 - q*v2
    return u1, v1, r1


def inverseEntier(a, n):
    u,v,d = euclideEtendu(a, n)
    return u % n


def puissanceRapide(a, m, n):
    b = 1
    if m == 0:
        return b
    else:
        ga = a
        bin_m = bin(m)[2:]
        for k in bin_m:
            ga = (ga**2) % n
            if k == 1:
                b = ga * b
        return b