import base64
import datetime
import hashlib
import logging
import os
import random
import re
import requests
import rsa
import urllib.parse as urllp

from Cryptodome.Cipher import AES


logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)
log = logging.getLogger("main")


def _check_folder_exist(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def zero_pad(text: str) -> bytes:
    if len(text) == 0:
        raise Exception("no data set")
    text = bytearray(text.encode())
    amount_to_pad = AES.block_size - (len(text) % AES.block_size)
    return text + b"\x00" * amount_to_pad


def encode_uri_component(s): return urllp.quote(s, safe="~()*!.'")


def grab(address: str, *, login: str = "admin", pwd: str = "admin",
         save_to: str = "./backups",
         hostname: str = "", timeout: tuple = (5, 5)) -> bool:
    try:
        if hostname == "":
            hostname = address

        r = requests.get(f"http://{address}/", timeout=(5, 5))
        if r.status_code != 200:
            raise Exception(f"{hostname} get version init -> {r.status_code}")

        new_locate = re.findall(r"\s+window.location =\"(.+)\";", r.text)[0]

        r = requests.get(f"http://{address}{new_locate}", timeout=(2, 2))

        if r.status_code != 200:
            raise Exception(f"{hostname} get version -> {r.status_code}")

        res = list(re.findall(r"[\s\S]+g_strFirmware = \"(.+)\";[\s\S]+g_rsa_n = \"(.+)\";[\s\S]+g_rsa_e = \"(.+)\";",
                              r.text))
        if len(res) == 0:
            version = list(re.findall(r"rsa.js\?(.+\d)\">", r.text))[0]
            if not version:
                raise Exception(f"{hostname} get version -> NaN")
            log.info(f"{hostname} version -> {version}")
            y = YealinkV80(address=address, login=login, pwd=pwd, save_to=save_to,
                           hostname=hostname, timeout=timeout)
            return y.save_config()

        res = res[0]
        session = r.headers.get("Set-Cookie", "").split("=")[1].split(";")[0]

        version, g_rsa_n, g_rsa_e = res
        log.info(f"{hostname} version -> {version}")
        y = Yealink84(g_rsa_n, g_rsa_e, session, address=address, login=login, pwd=pwd, save_to=save_to,
                      hostname=hostname, timeout=timeout)
        return y.save_config()

    except requests.exceptions.Timeout:
        raise Exception(f"{hostname} get version -> timeout")
    except Exception as e:
        raise Exception(f"{hostname} get version -> {e}")


class YealinkBase:
    def __init__(self, address: str, *, login: str = "admin", pwd: str = "admin",
                 save_to: str = "./backups",
                 hostname: str = "", timeout: tuple = (5, 5)):
        self.login = login
        self.pwd = pwd
        self.pubkey: rsa.PublicKey
        self.session: str
        self.address = address if "://" in address else "http://" + address
        self.hostname = hostname or self.address.split('/')[2]
        self.save_to = f'{save_to}/{self.hostname}'
        self.timeout = timeout
        self._header = {}
        self._res: str

    def __set_pubkey(self):
        res = self._res.split(",")

        if len(res) < 3:
            raise Exception(f"Response not full values: {res}")

        g_rsa_n = int(res[0], 16)
        g_rsa_e = int(res[1], 16)
        self.session = res[2]

        self.pubkey = rsa.PublicKey(g_rsa_n, g_rsa_e)

    @staticmethod
    def _random(to_bytes: bool = True) -> bytes | str:
        if to_bytes:
            return str(random.random()).encode()
        return str(random.random())

    def __generate_cipher(self) -> (str, bytearray):
        rand = self._random()
        data = hashlib.md5(rand).hexdigest()
        _data = data.encode()
        cipher = rsa.encrypt(_data, self.pubkey).hex()
        return cipher, bytearray.fromhex(data)

    def _create_auth_payload(self) -> str:
        pass

    def _encrypt_data(self) -> dict:
        self.__set_pubkey()

        cipher_key, key = self.__generate_cipher()
        cipher_iv, iv = self.__generate_cipher()
        data = self._create_auth_payload()
        encrypted = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = encrypted.encrypt(zero_pad(data))
        data = base64.b64encode(ciphertext).decode()

        return {
            "key": cipher_key,
            "iv": cipher_iv,
            "data": data,
            "jumpto": "status",
            "acc": ""
        }

    def _get_session_id(self, url: str):
        r = requests.get(url, timeout=self.timeout)
        if r.status_code != 200:
            log.debug(f"{self.hostname} - __get_session_id: {r.status_code}\n{r.content}\n")
            raise Exception(f"session status code response: {r.status_code}")
        self._res = r.text
        if r.headers.get("Set-Cookie"):
            self.session = r.headers.get("Set-Cookie", "").split("=")[1].split(";")[0]

    def _to_auth(self):
        """
        get session and return like header dict
        :return: session in header
        """
        pass

    def _save_backup(self, url: str, data: dict = {}, is_cfg: bool = True):
        try:
            r = requests.post(url=url, data=data, headers=self._header, timeout=self.timeout)
            if r.status_code != 200:
                log.debug(f"{self.hostname} - get config: {url}\nstatus code: {r.status_code}\n{r.content}\n")
                raise Exception("Error download config")

            _check_folder_exist(self.save_to)
        except Exception as e:
            log.error(e.__str__())
        else:
            suffix = ".cfg" if is_cfg else ".bin"
            path = f'{self.save_to}/{self.hostname}_{datetime.datetime.now().strftime("%Y-%m-%d")}{suffix}'
            with open(path, "wb") as f:
                f.write(r.content)
            log.info(f"{self.hostname} - config saved successfully: {path} ")

    def save_config(self) -> bool:
        try:
            self._to_auth()
            log.info(f"{self.hostname} - session corrected")
        except Exception as ec:
            log.error(f"{self.hostname} - save config: {e}\n")
        else:
            self._save_cfg()
            self._save_bin()
            return True

    def _save_cfg(self):
        pass

    def _save_bin(self):
        pass


class Yealink84(YealinkBase):
    def __init__(self, g_rsa_n: str = None, g_rsa_e: str = None, session: str = None, **kwargs):
        super().__init__(**kwargs)

        if (g_rsa_n or g_rsa_e or session) is None:
            self.__init_auth()
        else:
            self._res = f"{g_rsa_n},{g_rsa_e},{session}"

    def __init_auth(self):
        url = self.address + f"/servlet?m=mod_listener&p=login&q=loginForm&Random={self._random(False)}"
        self._get_session_id(url)

        if self._res is None or re.match(r"[\s\S]+g_rsa_n = \"(.+)\";[\s\S]+g_rsa_e = \"(.+)\";", self._res) is None:
            raise Exception(f"Response not valid or null: {self._res}")

        res = re.findall(r"[\s\S]+g_rsa_n = \"(.+)\";[\s\S]+g_rsa_e = \"(.+)\";", self._res)
        self._res = ",".join(list(res[0])) + "," + self.session

    def _create_auth_payload(self) -> str:
        return self._random(False) + ";" + self.session + ";" + self.pwd

    def _to_auth(self):
        """
        get session and return like header dict
        :return: session in header
        """
        
        encrypt_data = self._encrypt_data()

        data = encode_uri_component(encrypt_data["data"])
        cipher_key = encode_uri_component(encrypt_data["key"])
        cipher_iv = encode_uri_component(encrypt_data["iv"])

        payload = f"username={self.login}&pwd={data}&rsakey={cipher_key}&rsaiv={cipher_iv}"

        self._header = {
            "Cookie": f"SLG_G_WPT_TO=ru; SLG_GWPT_Show_Hide_tmp=1; SLG_wptGlobTipTmp=1; JSESSIONID={self.session}",
            "content-type": "application/x-www-form-urlencoded",
        }

        r = requests.post(self.address + f"/servlet?m=mod_listener&p=login&q=login",
                          data=payload, headers=self._header, allow_redirects=True, timeout=self.timeout)

        is_auth = re.match(r'[\s\S]+(\{"authstatus":"done"})', r.text)

        if r.status_code != 200 or is_auth is None:
            log.debug(f"{self.hostname} - auth: {r.status_code}\n{r.text}\n")
            raise Exception(f"The username or password is error!")
        log.info(f"{self.hostname} - auth: {is_auth.group(1)}")

    def _save_cfg(self):
        self._header["content-type"] = "multipart/form-data; boundary=----WebKitFormBoundaryDgBOm1oS8Eq30QKy"
        log.info(f"{self.hostname} - get and save config.cfg")
        url = self.address + "/servlet?m=mod_configfile&q=exportcfgconfig&type=all"
        self._save_backup(url)

    def _save_bin(self):
        log.info(f"{self.hostname} - get and save config.bin")
        url = self.address + "/servlet?m=mod_configfile&q=exportconfigbin"
        self._header["content-type"] = "multipart/form-data; boundary=----WebKitFormBoundaryXFtnKQ2nUR2scYrs"
        self._save_backup(url, is_cfg=False)


class YealinkV80(YealinkBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _create_auth_payload(self) -> str:
        data = f"rand={self._random()};"
        data += f"sessionid={self.session};"
        data += f"username={self.login};"
        data += f"pwd={self.pwd};"
        data = "MD5=" + hashlib.md5(data.encode()).hexdigest() + ";" + data
        return data

    def _to_auth(self):
        """
        get session and return like header dict
        :return: session in header
        """
        url = self.address + f"/servlet?p=login&q=getsessionid&random={self._random(False)}"

        self._get_session_id(url)

        if self._res is None or re.match(r"^[\w,-]+$", self._res) is None:
            raise Exception(f"Response not valid: {self._res}")

        payload = self._encrypt_data()

        self._header = {
            "Cookie": f"SLG_G_WPT_TO=ru; SLG_GWPT_Show_Hide_tmp=1; SLG_wptGlobTipTmp=1; JSESSIONID={self.session}",
        }

        r = requests.post(self.address + "/servlet?p=login&q=login", data=payload, headers=self._header,
                          allow_redirects=False, timeout=self.timeout)

        if r.status_code == 200:
            log.debug(f"{self.hostname} - auth: {r.status_code}\n{r.text}\n")
            raise Exception(f"The username or password is error!")

    def _save_cfg(self):
        self._header["content-type"] = "multipart/form-data; boundary=----WebKitFormBoundaryoMhAUuOaamEAB9Rk"
        data = {
            "body": "------WebKitFormBoundaryoMhAUuOaamEAB9Rk\r\nContent-Disposition: form-data; "
                    "name=\"token\"\r\n\r\n327915891\r\n------WebKitFormBoundaryoMhAUuOaamEAB9Rk\r\nContent"
                    "-Disposition: form-data; name=\"localConfigFile\"; filename=\"\"\r\nContent-Type: "
                    "application/octet-stream\r\n\r\n\r\n------WebKitFormBoundaryoMhAUuOaamEAB9Rk--\r\n"
        }
        log.info(f"{self.hostname} - get and save config.cfg")
        url = self.address + "/servlet?p=settings-config&q=localconfig&type=export&configfile=1"
        self._save_backup(url, data)

    def _save_bin(self):
        log.info(f"{self.hostname} - get and save config.bin")
        url = self.address + "/servlet?p=settings-config&q=export"
        self._header["content-type"] = "application/x-www-form-urlencoded"
        data = {"token": 1548085803}
        self._save_backup(url, data, is_cfg=False)


if __name__ == "__main__":
    try:
        log.info("Start")
        
        grab("192.168.1.2", login="admin", pwd="admin", hostname="test")

        log.info("Done")
    except Exception as e:
        log.error(e.__str__())
