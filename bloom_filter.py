class BloomFilter:
    def __init__(self, size=1000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, item):
        item = item.encode('utf-8')
        return [int(hashlib.sha256(item + str(i).encode('utf-8')).hexdigest(), 16) % self.size for i in range(self.hash_count)]

    def add(self, item):
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1

    def __contains__(self, item):
        return all(self.bit_array[hash_val] for hash_val in self._hashes(item))
