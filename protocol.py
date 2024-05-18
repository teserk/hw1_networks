import socket
import time
from queue import PriorityQueue


class TCPSegment:
    service_len = 8 + 8
    ack_timeout = 0.01

    def __init__(self, seq_number: int, ack_number: int, data: bytes):
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.data = data
        self.acknowledged = False
        self._sending_time = time.time()

    def dump(self) -> bytes:
        seq = self.seq_number.to_bytes(8, "big", signed=False)
        ack = self.ack_number.to_bytes(8, "big", signed=False)
        return seq + ack + self.data

    @staticmethod
    def load(data: bytes) -> 'TCPSegment':
        seq = int.from_bytes(data[:8], "big", signed=False)
        ack = int.from_bytes(data[8:16], "big", signed=False)
        return TCPSegment(seq, ack, data[TCPSegment.service_len:])

    def update_sending_time(self, sending_time=None):
        self._sending_time = sending_time if sending_time is not None else time.time()

    @property
    def expired(self):
        return not self.acknowledged and (time.time() - self._sending_time > self.ack_timeout)

    def __len__(self):
        return len(self.data)

    def __lt__(self, other):
        return self.seq_number < other.seq_number

    def __eq__(self, other):
        return self.seq_number == other.seq_number


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.max_segment_size = 1500
        self.window_size = self.max_segment_size * 12
        self.ack_crit_attempts = 20

        self._sent_bytes_n = 0
        self._confirmed_bytes_n = 0
        self._received_bytes_n = 0
        self._send_window = PriorityQueue()
        self._recv_window = PriorityQueue()
        self._buffer = bytes()

    def send(self, data: bytes) -> int:
        sent_data_len = 0
        attempt = 0
        while (data or self._confirmed_bytes_n < self._sent_bytes_n) and (attempt < self.ack_crit_attempts):
            window_lock = (self._sent_bytes_n - self._confirmed_bytes_n > self.window_size)
            if not window_lock and data:
                right_border = min(self.max_segment_size, len(data))
                sent_length = self._send_segment(TCPSegment(self._sent_bytes_n,
                                                            self._received_bytes_n,
                                                            data[: right_border]))
                data = data[sent_length:]
                sent_data_len += sent_length
                self._receive_segment(0.0)
            else:
                # Для дальнейшей работы нужно подтвердить доставку сообщения
                if self._receive_segment(TCPSegment.ack_timeout):
                    # Получатель следит за сетью и присылает подтверждения
                    attempt = 0
                else:
                    # Пакеты были потеряны в сети или получатель не следит больше за ней
                    attempt += 1
            self._resend_earliest_segment()

        return sent_data_len

    def recv(self, n: int) -> bytes:
        # # print(f'{self.name} expects {n} bytes. ')
        right_border = min(n, len(self._buffer))
        data = self._buffer[:right_border]
        self._buffer = self._buffer[right_border:]
        while len(data) < n:
            self._receive_segment()
            right_border = min(n, len(self._buffer))
            data += self._buffer[:right_border]
            self._buffer = self._buffer[right_border:]
            # print(f'{self.name} have read {len(data)} bytes, totally {self._received_bytes_n} bytes. ')
        # print(f'{self.name} have read expected {n} bytes. ')

        return data

    def _receive_segment(self, timeout: float = None) -> bool:
        self.udp_socket.settimeout(timeout)
        try:
            segment = TCPSegment.load(self.recvfrom(self.max_segment_size + TCPSegment.service_len))
        except socket.error:
            return False

        if len(segment):
            self._recv_window.put((segment.seq_number, segment), block=False)
            self._shift_recv_window()

        if segment.ack_number > self._confirmed_bytes_n:
            self._confirmed_bytes_n = segment.ack_number
            self._shift_send_window()

        return True

    def _send_segment(self, segment: TCPSegment) -> int:
        """
        @return: длина отправленных данных
        """
        self.udp_socket.settimeout(None)
        just_sent = self.sendto(segment.dump()) - segment.service_len

        if segment.seq_number == self._sent_bytes_n:
            self._sent_bytes_n += just_sent
        elif segment.seq_number > self._sent_bytes_n:
            raise ValueError("sent too many")

        if len(segment):
            segment.data = segment.data[: just_sent]
            segment.update_sending_time()
            self._send_window.put((segment.seq_number, segment), block=False)

        return just_sent

    def _shift_recv_window(self):
        earliest_segment = None
        while not self._recv_window.empty():
            _, earliest_segment = self._recv_window.get(block=False)
            if earliest_segment.seq_number < self._received_bytes_n:
                earliest_segment.acknowledged = True
            elif earliest_segment.seq_number == self._received_bytes_n:
                self._buffer += earliest_segment.data
                self._received_bytes_n += len(earliest_segment)
                earliest_segment.acknowledged = True
            else:
                self._recv_window.put((earliest_segment.seq_number, earliest_segment), block=False)
                break

        if earliest_segment:
            self._send_segment(TCPSegment(self._sent_bytes_n, self._received_bytes_n, bytes()))

    def _shift_send_window(self):
        while not self._send_window.empty():
            _, earliest_segment = self._send_window.get(block=False)
            if earliest_segment.seq_number >= self._confirmed_bytes_n:
                self._send_window.put((earliest_segment.seq_number, earliest_segment), block=False)
                break

    def _resend_earliest_segment(self, force=False):
        if self._send_window.empty():
            return
        _, earliest_segment = self._send_window.get(block=False)
        if earliest_segment.expired or force:
            self._send_segment(earliest_segment)
        else:
            self._send_window.put((earliest_segment.seq_number, earliest_segment), block=False)
