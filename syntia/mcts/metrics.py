from __future__ import division


def bitcount(v):
    """
    Number of set bits in v
    :param v: int
    :return: int
    """
    return bin(v).count("1")


def leading_zeros(v, bitsize):
    """
    Count leading zeros
    :param v: int
    :param  bitsize: bit length
    :return: int, leading zeros of v
    """
    # padd bit string
    s = format(v, "0{}b".format(bitsize))

    return len(s) - len(s.lstrip('0'))


def trailing_zeros(v, bitsize):
    """
    Count trailing zeros
    :param v: int
    :param bitsize: int
    :return: int, leading zeros of v
    """
    # padd bit string
    s = format(v, "0{}b".format(bitsize))

    return len(s) - len(s.rstrip('0'))


def leading_ones(v, bitsize):
    """
    Count leading ones
    :param v: int
    :param  bitsize: bit length
    :return: int, leading ones of v
    """
    # padd bit string
    s = format(v, "0{}b".format(bitsize))

    return len(s) - len(s.lstrip('1'))


def trailing_ones(v, bitsize):
    """
    Count trailing zeros
    :param v: int
    :param bitsize: int
    :return: int, leading ones of v
    """
    # padd bit string
    s = format(v, "0{}b".format(bitsize))

    return len(s) - len(s.rstrip('1'))


def num_distance(a, b):
    """
    Numeric distance of a and b
    :param a: int
    :param b: int
    :return: int
    """
    return abs(a - b)


def rotate_left(a, b, size):
    """
    Rotates bits of a to the left b times

    :param a: int to shift
    :param b: int, number of shifts
    :param size: bit length
    :return: int
    """
    shift = b & (size - 1)
    return ((a << shift) | (a >> size - shift)) % 2 ** size


def metric_hamming_distance(a, b, bitsize):
    """
    Hamming distance
    :param a: int
    :param b: int
    :param bitsize: int
    :return: flaot
    """
    n = bitcount(a ^ b)
    return 1 - (n / bitsize)


def metric_leading_zeros(a, b, bitsize):
    """
    Numeric difference of the leading
    zeros from a and b
    :param a: int
    :param b: int
    :param bitsize: int
    :return: float
    """
    # leading zeros
    a = leading_zeros(a, bitsize)
    b = leading_zeros(b, bitsize)

    # numeric difference
    n = abs(a - b)

    return 1 - float(n / bitsize)


def metric_trailing_zeros(a, b, bitsize):
    """
    Numeric difference of the trailing
    zeros from a and b
    :param a: int
    :param b: int
    :param bitsize: int
    :return: float
    """
    # leading zeros
    a = trailing_zeros(a, bitsize)
    b = trailing_zeros(b, bitsize)

    # numeric difference
    n = abs(a - b)

    return 1 - float(n / bitsize)


def metric_leading_ones(a, b, bitsize):
    """
    Numeric difference of the leading
    ones from a and b
    :param a: int
    :param b: int
    :param bitsize: int
    :return: float
    """
    # leading ones
    a = leading_ones(a, bitsize)
    b = leading_ones(b, bitsize)

    # numeric difference
    n = abs(a - b)

    return 1 - float(n / bitsize)


def metric_trailing_ones(a, b, bitsize):
    """
    Numeric difference of the trailing
    ones from a and b
    :param a: int
    :param b: int
    :param bitsize: int
    :return: float
    """
    # trailing ones
    a = trailing_ones(a, bitsize)
    b = trailing_ones(b, bitsize)

    # numeric difference
    n = abs(a - b)

    return 1 - float(n / bitsize)


def metric_num_distance(a, b):
    """
    Numeric distance of a and b.
    Normalised with their local
    maximum.
    :param a: int
    :param b: int
    :return: float
    """
    # numeric distance
    d = num_distance(a, b)

    # avoid division by 0
    if a == b:
        return 1
    else:
        # maximum of a and b
        maximum = max([abs(a), abs(b)])
        return 1 - (d / maximum)


def distance_metric(a, b, bitsize):
    """
    Combines different distance metrics
    :param a: int
    :param b: int
    :param bitsize: int
    :return: float
    """
    # initial score
    score = 0.0

    # apply metrics
    for x, y in [(a, b)]:
        score += metric_hamming_distance(x, y, bitsize)
        score += metric_leading_zeros(x, y, bitsize)
        score += metric_trailing_zeros(x, y, bitsize)
        score += metric_leading_ones(x, y, bitsize)
        score += metric_trailing_ones(x, y, bitsize)
        score += metric_num_distance(x, y)

    # normalise weights
    d = score / 6

    return d
