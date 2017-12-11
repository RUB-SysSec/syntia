PAGESIZE = 4096


class Memory(dict):
    def __init__(self):
        super(Memory, self).__init__()
        self.mapped = set()
        self.mapping_requests = dict()

    def map(self, addr, size):
        for offset in xrange(size):
            self.mapped.add(addr + offset)

        self.mapping_requests[addr] = size


    def unmap(self, addr, size):
        for offset in xrange(size):
            self.mapped.remove(addr + offset)

    def is_mapped(self, addr, size):
        for offset in xrange(size):
            if (addr + offset) not in self.mapped:
                return False
        return True