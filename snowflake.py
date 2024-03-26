import time
import threading

class SnowflakeGenerator:
    def __init__(self, datacenter_id, worker_id):
        # 41 位时间戳部分的偏移量和起始时间（一般取系统的当前时间）
        self.epoch = 1609459200000  # 2021-01-01T00:00:00Z

        # 机器标识位数
        self.datacenter_id_bits = 5
        self.worker_id_bits = 5

        # 序列号位数
        self.sequence_bits = 12

        # 最大值
        self.max_datacenter_id = -1 ^ (-1 << self.datacenter_id_bits)
        self.max_worker_id = -1 ^ (-1 << self.worker_id_bits)

        # 移位
        self.worker_id_shift = self.sequence_bits
        self.datacenter_id_shift = self.sequence_bits + self.worker_id_bits
        self.timestamp_shift = self.sequence_bits + self.worker_id_bits + self.datacenter_id_bits

        self.datacenter_id = datacenter_id
        self.worker_id = worker_id
        self.sequence = 0
        self.last_timestamp = -1

        # 锁
        self.lock = threading.Lock()

    def _til_next_millis(self, last_timestamp):
        timestamp = int(time.time() * 1000)
        while timestamp <= last_timestamp:
            timestamp = int(time.time() * 1000)
        return timestamp

    def next_id(self):
        with self.lock:
            timestamp = int(time.time() * 1000)
            if timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & ((1 << self.sequence_bits) - 1)
                if self.sequence == 0:
                    timestamp = self._til_next_millis(self.last_timestamp)
            else:
                self.sequence = 0

            self.last_timestamp = timestamp

            return ((timestamp - self.epoch) << self.timestamp_shift) | \
                   (self.datacenter_id << self.datacenter_id_shift) | \
                   (self.worker_id << self.worker_id_shift) | \
                   self.sequence

#使用实例
#idgenerator = SnowflakeGenerator(datacenter_id=1, worker_id=1)
#device_id = idgenerator.next_id()
#print(device_id)
