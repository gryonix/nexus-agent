#!/usr/bin/env python3
import base64, fcntl, os, re, select, struct, subprocess, sys, time

PIPE = os.environ.get("CEC_VOLUME_PIPE", "/run/shairport-sync/metadata")
DEV = os.environ.get("CEC_VOLUME_DEVICE", "/dev/cec0")
MIN = int(os.environ.get("CEC_VOLUME_MIN", "1"))
MAX = int(os.environ.get("CEC_VOLUME_MAX", "40"))
ITEM = re.compile(r"<item><type>(\w+)</type><code>(\w+)</code>.*?</item>", re.S)
DATA = re.compile(r'<data encoding="base64">\s*([^<]*)<', re.S)
CEC_TRANSMIT = 0xC0386105
CEC_MESSAGE = "=QQIIII16s7Bx"
SPEAKER = 0xB5
BROADCAST = 0xBF
PLAY_CODES = {"70626567", "7072736d"}
VOLUME_CODE = "70766f6c"
PER_PRESS = 1.2
FD = None
AWAKE_UNTIL = 0.0


def log(text):
    print(text, flush=True)


def reconnect():
    global FD
    if FD is not None:
        os.close(FD)
    subprocess.run(["cec-ctl", "-d", DEV, "-s", "--playback"], capture_output=True)
    FD = os.open(DEV, os.O_RDWR)


def raw_send(message, reply, timeout):
    packed = struct.pack(CEC_MESSAGE, 0, 0, len(message), timeout, 0, 0,
                         bytes(message).ljust(16, b"\0"), reply, 0, 0, 0, 0, 0, 0)
    buffer = bytearray(packed)
    fcntl.ioctl(FD, CEC_TRANSMIT, buffer)
    return struct.unpack(CEC_MESSAGE, bytes(buffer))


def send(message, reply=0, timeout=1000):
    try:
        return raw_send(message, reply, timeout)
    except OSError:
        reconnect()
        return raw_send(message, reply, timeout)


def current():
    answer = send([SPEAKER, 0x71], reply=0x7A)
    return answer[6][2] & 0x7F if answer[8] == 1 else None


def is_awake():
    answer = send([SPEAKER, 0x8F], reply=0x90)
    return answer[8] == 1 and answer[6][2] == 0


def wake():
    global AWAKE_UNTIL
    if time.time() < AWAKE_UNTIL:
        return
    if is_awake():
        AWAKE_UNTIL = time.time() + 20
        return
    log("waking the speaker")
    send([SPEAKER, 0x44, 0x6D], timeout=0)
    send([SPEAKER, 0x45], timeout=0)
    send([BROADCAST, 0x82, 0x11, 0x00], timeout=0)
    time.sleep(2)


def percent(airplay_db):
    if airplay_db <= -144:
        return 0
    scaled = MIN + (airplay_db + 30) / 30 * (MAX - MIN)
    return max(MIN, min(MAX, round(scaled)))


def items(text):
    while found := ITEM.search(text):
        item, text = found.group(0), text[found.end():]
        data = DATA.search(item)
        yield found.group(2), data.group(1) if data else "", text


class Regulator:
    def __init__(self):
        self.pending = ""
        self.target = None
        self.estimate = None
        self.direction = 0

    def read(self, fd):
        chunk = os.read(fd, 4096)
        if not chunk:
            return False
        self.pending += chunk.decode(errors="ignore")
        for code, data, rest in items(self.pending):
            self.pending = rest
            if code in PLAY_CODES:
                wake()
            elif code == VOLUME_CODE:
                db = float(base64.b64decode(data).decode().split(",")[0])
                log(f"airplay volume {db} dB")
                wake()
                self.target = percent(db)
        return True

    def release(self):
        if self.direction:
            send([SPEAKER, 0x45], timeout=0)
            self.direction = 0

    def press(self, direction):
        if self.direction and self.direction != direction:
            self.release()
        send([SPEAKER, 0x44, 0x41 if direction > 0 else 0x42], timeout=0)
        self.direction = direction
        self.estimate += direction * PER_PRESS

    def settle(self):
        self.release()
        time.sleep(0.05)
        self.estimate = current()
        if self.estimate is None or abs(self.estimate - self.target) <= 1:
            log(f"speaker volume {self.estimate} (wanted {self.target})")
            self.target = None

    def work(self):
        if self.estimate is None:
            self.estimate = current()
        if self.estimate is None:
            self.target = None
        elif abs(self.target - self.estimate) >= PER_PRESS / 2:
            self.press(1 if self.target > self.estimate else -1)
        else:
            self.settle()

    def run(self, fd):
        while True:
            busy = self.target is not None
            waiting = select.select([fd], [], [], 0 if busy else 30)[0]
            if waiting and not self.read(fd):
                self.release()
                return
            if not waiting and not busy:
                self.estimate = None
            if self.target is not None:
                self.work()


def main():
    reconnect()
    while True:
        try:
            fd = os.open(PIPE, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            time.sleep(2)
            continue
        try:
            Regulator().run(fd)
        except Exception as error:
            log(f"error: {error}")
        os.close(fd)
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
