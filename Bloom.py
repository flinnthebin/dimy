import bitarray
import hashlib

#####################
#                   #
#      CONFIG       #
#                   #
#####################

BF_SIZE=100*1024*8
HASH_NUM=3

#####################
#                   #
#      CONFIG       #
#                   #
#####################

class BloomFilter:
    def __init__(self, size=BF_SIZE, num_hashes=HASH_NUM):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, enc_id):
        enc_id = enc_id.encode('utf-8')
        return [int(hashlib.sha256(enc_id + str(i).encode('utf-8')).hexdigest(), 16) % self.size for i in range(self.num_hashes)]

    def add(self, enc_id):
        for hash in self._hashes(enc_id):
            self.bit_array[hash] = 1

    def __contains__(self, enc_id):
        return all(self.bit_array[hash] for hash in self._hashes(enc_id))
