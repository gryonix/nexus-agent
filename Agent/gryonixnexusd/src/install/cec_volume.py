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
TV = 0xB0
BROADCAST = 0xBF
PLAY_CODES = {"70626567", "7072736d"}
VOLUME_CODE = "70766f6c"
CONTAINER = "shairport-sync"
WATCH_SECONDS = 1
PLAY_GRACE = int(os.environ.get("CEC_VOLUME_GRACE", "15"))
OFF_SECONDS = int(os.environ.get("CEC_VOLUME_OFF_DELAY", "2"))
TV_WAIT = int(os.environ.get("CEC_VOLUME_TV_WAIT", "60"))
DISCONNECT = os.environ.get("CEC_VOLUME_DISCONNECT", "1") == "1"
PER_PRESS = 1.2
RETRIES = 60
TV_OFF = os.environ.get("CEC_VOLUME_TV_OFF", "1") == "1"
FD = None
AWAKE_UNTIL = 0.0
SELECTED_UNTIL = 0.0


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
    for attempt in range(RETRIES):
        try:
            return raw_send(message, reply, timeout)
        except OSError:
            if attempt == RETRIES - 1:
                raise
            time.sleep(0.5)
            try:
                reconnect()
            except OSError:
                pass


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
    deadline = time.time() + 15
    while time.time() < deadline and not is_awake():
        time.sleep(0.5)
    time.sleep(1)


def tv_power():
    answer = send([TV, 0x8F], reply=0x90)
    return answer[6][2] if answer[8] == 1 else None


def put_tv_to_standby():
    deadline = time.time() + TV_WAIT
    while time.time() < deadline:
        state = tv_power()
        if state in (1, 3):
            log("TV is in standby")
            return
        if state in (0, 2):
            send([TV, 0x36], timeout=0)
            time.sleep(3)
        else:
            time.sleep(1)


def select_input():
    global SELECTED_UNTIL
    if time.time() < SELECTED_UNTIL:
        return
    SELECTED_UNTIL = time.time() + 30
    tv_state = tv_power()
    log(f"selecting the input, TV power {tv_state}")
    send([BROADCAST, 0x82, 0x11, 0x00], timeout=0)
    if TV_OFF and tv_state == 1:
        put_tv_to_standby()


def audio_running():
    number = re.search(r"(\d+)$", DEV)
    path = f"/proc/asound/card{number.group(1) if number else 0}/pcm0p/sub0/status"
    try:
        with open(path) as status:
            return "RUNNING" in status.read()
    except OSError:
        return False


def speaker_standby():
    try:
        answer = raw_send([SPEAKER, 0x8F], 0x90, 1000)
    except OSError:
        return False
    return answer[8] == 1 and answer[6][2] in (1, 3)


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
        self.wanted = None
        self.running_since = None
        self.down_since = None
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
                select_input()
                self.target = self.wanted
            elif code == VOLUME_CODE:
                db = float(base64.b64decode(data).decode().split(",")[0])
                log(f"airplay volume {db} dB")
                wake()
                self.wanted = self.target = percent(db)
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

    def drop_if_speaker_off(self):
        if not DISCONNECT:
            return
        if not audio_running():
            self.running_since = self.down_since = None
            return
        self.running_since = self.running_since or time.time()
        if time.time() - self.running_since < PLAY_GRACE:
            return
        if not speaker_standby():
            self.down_since = None
            return
        if not self.down_since:
            log("speaker went to standby")
        self.down_since = self.down_since or time.time()
        if time.time() - self.down_since < OFF_SECONDS:
            return
        log("speaker is off, disconnecting AirPlay")
        subprocess.run(["docker", "restart", CONTAINER], capture_output=True)
        self.running_since = self.down_since = None

    def run(self, fd):
        while True:
            busy = self.target is not None
            idle = WATCH_SECONDS
            waiting = select.select([fd], [], [], 0 if busy else idle)[0]
            if waiting and not self.read(fd):
                self.release()
                return
            if not waiting and not busy:
                self.estimate = None
            self.drop_if_speaker_off()
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
