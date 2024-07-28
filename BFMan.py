from Bloom import BloomFilter
import time
from collections import deque

class BFMan:
    def __init__(self, dbf_duration=90, max_dbfs=2):
        self.dbf_duration = dbf_duration
        self.max_dbfs = max_dbfs
        self.dbfs = deque()
        self.current_dbf = BloomFilter()
        self.start_time = time.time()
        self.qbf_start_time = self.start_time
        self.qbf = BloomFilter()
        self.dbf_counter = 1
        self.qbf_created = False
        print(f"\033[36mDBF CREATED\033[0m (1 of {self.max_dbfs})")

    def add_enc_id(self, enc_id):
        current_time = time.time()
        if current_time - self.start_time >= self.dbf_duration:
            self._rotate_dbf()
        self.current_dbf.add(enc_id)

    def _rotate_dbf(self):
        if len(self.dbfs) >= self.max_dbfs:
            self.dbfs.popleft()
        self.dbfs.append(self.current_dbf)
        self.current_dbf = BloomFilter()
        self.dbf_counter += 1
        if self.dbf_counter > self.max_dbfs:
            self.dbf_counter = 1
        print(f"\033[36mDBF CREATED\033[0m ({self.dbf_counter} of {self.max_dbfs})")
        self.start_time = time.time()

    def contains(self, enc_id):
        for dbf in self.dbfs:
            if enc_id in dbf:
                return True
        return enc_id in self.current_dbf or enc_id in self.qbf

    def query_filter(self):
        current_time = time.time()
        if current_time - self.qbf_start_time >= self.dbf_duration * self.max_dbfs:
            print(f"\033[93mCREATING QBF\033[0m")
            self.qbf = BloomFilter()
            for dbf in self.dbfs:
                for i in range(dbf.size):
                    if dbf.bit_array[i]:
                        self.qbf.bit_array[i] = 1
            self.dbfs.clear()
            self.qbf_created = True
            self.qbf_start_time = current_time
            print(f"\033[36mQBF CREATED\033[0m")

    def is_qbf_created(self):
        if self.qbf_created:
            self.qbf_created = False
            return True
        return False

    def contact_filter(self):
        print(f"\033[93mCREATING CBF\033[0m")
        cbf = BloomFilter()
        for dbf in self.dbfs:
            for i in range(dbf.size):
                if dbf.bit_array[i]:
                    cbf.bit_array[i] = 1
        for i in range(self.current_dbf.size):
            if self.current_dbf.bit_array[i]:
                cbf.bit_array[i] = 1
        print(f"\033[36mCBF CREATED\033[0m")
        return cbf
