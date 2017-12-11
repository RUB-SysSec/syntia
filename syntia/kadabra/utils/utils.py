def reverse_bytes(s):
    """
    Reverses a byte string: aabb => bbaa
    :param s: string
    :return: reversed string
    """
    new = []
    for i in xrange(0, len(s), 2):
        new.append(s[i:i + 2])
    return "".join(reversed(new))


def int_to_hex(v, size):
    """
    Transforms an int into an hex string
    :param v: int
    :param size: size of int
    :return: string
    """
    # pad bit string
    s = format(v, "0{}x".format(size * 2))
    # reverse and decode
    s = reverse_bytes(s).decode("hex")

    return s


def addr_to_int(addr):
    """
    Transforms little-endian memory address into an int
    :param addr:
    :return: int
    """
    return int(reverse_bytes(str(addr).encode("hex")), 16)


def to_unsinged(v, size):
    """
    Transforms an signed int into an unsigned int
    :param v: signed int
    :param size: size of unsigned int
    :return: unsigned int
    """
    return v & (2 ** size - 1)
