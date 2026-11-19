#!/usr/bin/env python3
import fcntl, glob, os, struct, subprocess, time

DIRECTORY = os.environ.get("SPEAKER_POWER_DIR", "/run/gryonixnexus/speaker-power")
DEVICE = os.environ.get("SPEAKER_POWER_DEVICE", "")
HDMI = os.environ.get("SPEAKER_POWER_HDMI", "0") == "1"
ENTRIES = os.environ.get("SPEAKER_POWER_ENTRIES", "/etc/gryonixnexus/speaker-power.d")
CEC_TRANSMIT = 0xC0386105
CEC_RECEIVE = 0xC0386106
CEC_S_MODE = 0x40046109
INITIATOR_AND_FOLLOWER = 0x11
CEC_MESSAGE = "=QQIIII16s7Bx"
OWN = 0xB
AUDIO = 5
TV = 0
BROADCAST = 0xF
ACTIVE_SOURCE = 0x82
STANDBY = 0x36
POWER_PRESSED = [0x44, 0x6D]
POWER_RELEASED = [0x45]
STATUS_REQUEST = 0x8F
STATUS_REPLY = 0x90
STANDBY_STATES = (1, 3)
WATCH_SECONDS = 1
SEARCH_SECONDS = 30


def log(text):
    print(text, flush=True)


def parse_services(text):
    # name:on:off:delay[:card[:hdmi[:device]]] entries split by commas.
    found = {}
    for entry in filter(None, text.split(",")):
        parts = entry.split(":") + [""] * 7
        found[parts[0]] = {"on": parts[1] == "1", "off": parts[2] == "1",
                           "delay": int(parts[3]), "card": parts[4],
                           "hdmi": parts[5] == "1", "device": parts[6]}
    return found


def read_entries():
    # One entry file per audio service.
    lines = []
    for path in sorted(glob.glob(os.path.join(ENTRIES, "*"))):
        try:
            with open(path) as entry:
                lines.append(entry.read().strip())
        except OSError:
            pass
    try:
        return parse_services(",".join(lines))
    except (ValueError, IndexError):
        return {}


def header(target):
    if target == BROADCAST:
        raise ValueError("power is never sent to everyone")
    return OWN << 4 | target


def power_on_messages():
    return [[header(AUDIO)] + POWER_PRESSED, [header(AUDIO)] + POWER_RELEASED]


def standby_message():
    return [header(AUDIO), STANDBY]


class Policy:
    def __init__(self, services, guard):
        self.services = services
        self.guard = guard
        self.playing = set()
        self.stopped_at = None
        self.last = None
        self.foreign = False

    def saw_foreign_source(self):
        self.foreign = True

    def tick(self, now, active):
        active = {name for name in active if name in self.services}
        action = None
        if active and not self.playing:
            self.foreign = False
            self.stopped_at = None
            if any(self.services[name]["on"] for name in active):
                action = "on"
        for name in sorted(self.playing - active):
            self.last = name
        if self.playing and not active:
            self.stopped_at = now
        if not active and self.stopped_at is not None and self.due(now):
            self.stopped_at = None
            if not self.foreign and self.guard():
                action = "off"
        self.playing = active
        return action

    def due(self, now):
        service = self.services.get(self.last)
        if service is None or not service["off"]:
            self.stopped_at = None
            return False
        return now - self.stopped_at >= service["delay"]


def card_running(card):
    for path in glob.glob(f"/proc/asound/{card}/pcm*p/sub*/status"):
        try:
            with open(path) as status:
                if "RUNNING" in status.read():
                    return True
        except OSError:
            pass
    return False


def file_state(name):
    try:
        with open(os.path.join(DIRECTORY, name)) as state:
            return state.read().strip() == "on"
    except OSError:
        return False


def active_services(services):
    # Sound-card entries count only while no player reports a session.
    events = {name for name in services if file_state(name)}
    if events:
        return events
    return {name for name, info in services.items()
            if info["card"] and card_running(info["card"])}


def hdmi_running():
    for path in glob.glob("/proc/asound/card*/id"):
        try:
            with open(path) as card:
                if "hdmi" in card.read().lower() and card_running(path.split("/")[3]):
                    return True
        except OSError:
            pass
    return False


class Link:
    def __init__(self):
        self.path = None
        self.fd = None
        self.follower = None
        self.searched_at = 0.0
        self.device = DEVICE

    def close(self):
        for fd in (self.fd, self.follower):
            if fd is not None:
                os.close(fd)
        self.path = self.fd = self.follower = None

    def candidates(self):
        return [self.device] if self.device else sorted(glob.glob("/dev/cec*"))

    def ensure(self):
        if self.path:
            return True
        if time.time() - self.searched_at < SEARCH_SECONDS:
            return False
        self.searched_at = time.time()
        for path in self.candidates():
            try:
                subprocess.run(["cec-ctl", "-d", path, "-s", "--playback"], capture_output=True)
                self.fd = os.open(path, os.O_RDWR)
                self.path = path
                if (self.device or self.power_state(AUDIO) is not None) and self.follow():
                    return True
            except OSError:
                pass
            self.close()
        return False

    def follow(self):
        try:
            self.follower = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
            fcntl.ioctl(self.follower, CEC_S_MODE, struct.pack("=I", INITIATOR_AND_FOLLOWER))
        except OSError:
            return False
        log(f"speaker found on {self.path}")
        return True

    def send(self, message, reply=0, timeout=1000):
        packed = struct.pack(CEC_MESSAGE, 0, 0, len(message), timeout, 0, 0,
                             bytes(message).ljust(16, b"\0"), reply, 0, 0, 0, 0, 0, 0)
        buffer = bytearray(packed)
        fcntl.ioctl(self.fd, CEC_TRANSMIT, buffer)
        return struct.unpack(CEC_MESSAGE, bytes(buffer))

    def power_state(self, target):
        answer = self.send([header(target), STATUS_REQUEST], STATUS_REPLY)
        return answer[6][2] if answer[8] == 1 else None

    def sources(self):
        # Yields initiators of Active Source broadcasts from others.
        while self.follower is not None:
            buffer = bytearray(struct.calcsize(CEC_MESSAGE))
            try:
                fcntl.ioctl(self.follower, CEC_RECEIVE, buffer)
            except OSError:
                return
            fields = struct.unpack(CEC_MESSAGE, bytes(buffer))
            message = list(fields[6][:fields[2]])
            if len(message) > 1 and message[1] == ACTIVE_SOURCE and message[0] >> 4 != OWN:
                yield message[0] >> 4


class Runner:
    def __init__(self):
        self.services = read_entries()
        self.link = Link()
        self.policy = Policy(self.services, self.tv_in_standby)

    def reload(self):
        self.services = self.policy.services = read_entries()
        devices = [info["device"] for info in self.services.values() if info["device"]]
        self.link.device = devices[0] if devices else DEVICE

    def on_hdmi(self):
        playing = [self.services[name] for name in self.policy.playing if name in self.services]
        return HDMI or any(info["hdmi"] for info in playing) or hdmi_running()

    def tv_in_standby(self):
        if not self.link.ensure():
            return True
        try:
            state = self.link.power_state(TV)
        except OSError:
            return True
        return state is None or state in STANDBY_STATES

    def wake(self):
        if not self.on_hdmi() or not self.link.ensure():
            return
        log("switching the speaker on")
        try:
            for message in power_on_messages():
                self.link.send(message, timeout=0)
        except OSError as error:
            log(f"switch on: {error}")
            self.link.close()

    def sleep(self):
        if not self.link.ensure():
            return
        try:
            if self.link.power_state(AUDIO) in STANDBY_STATES:
                return
            log("switching the speaker off")
            self.link.send(standby_message(), timeout=0)
        except OSError as error:
            log(f"switch off: {error}")
            self.link.close()

    def step(self):
        self.reload()
        self.link.ensure()
        for _ in self.link.sources():
            self.policy.saw_foreign_source()
        action = self.policy.tick(time.time(), active_services(self.services))
        if action == "on":
            self.wake()
        elif action == "off":
            self.sleep()

    def run(self):
        os.makedirs(DIRECTORY, exist_ok=True)
        os.chmod(DIRECTORY, 0o1777)
        while True:
            self.step()
            time.sleep(WATCH_SECONDS)


def main():
    Runner().run()


if __name__ == "__main__":
    main()
