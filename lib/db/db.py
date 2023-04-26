from pinlib import decrypt, encrypt
from pathlib import Path
from hmac import compare_digest
from wallycore import ec_sig_to_public_key, sha256, hmac_sha256, hex_from_bytes, AES_KEY_LEN_256, EC_SIGNATURE_RECOVERABLE_LEN, SHA256_LEN, hex_to_bytes
from dotenv import load_dotenv

import os
import time
import struct
import redis

# consts
b2h = hex_from_bytes
h2b = hex_to_bytes
VERSION = 0
load_dotenv()

'''
@brief: REDIS Functionalities
'''
redis_host = os.environ.get('REDIS_HOST')
redis_port = int(os.environ.get('REDIS_PORT', 6379))
redis_health_check_interval = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 25))
redis_password = os.environ.get('REDIS_PASSWORD', None)
red_conn = redis.Redis(host=redis_host, port=redis_port, db=0, password=redis_password,
                       health_check_interval=redis_health_check_interval,
                       retry_on_timeout=True)


'''
@brief: File Storage & Functionalities
'''
class FileStorage(object):

    '''
    @brief: Get File Name
    '''
    @staticmethod
    def _get_filename(key):
        filename = '{}.pin'.format(b2h(key))
        if os.path.exists('pins'):
            return Path('pins') / filename
        return filename
    
    '''
    @brief: get filename
    '''
    @classmethod
    def get(cls, key):
        with open(cls._get_filename(key), 'rb') as f:
            return f.read()

    '''
    @brief: set method
    '''
    @classmethod
    def set(cls, key, data):
        with open(cls._get_filename(key), 'wb') as f:
            f.write(data)

    '''
    @brief: already exists method
    '''
    @classmethod
    def exists(cls, key):
        return os.path.exists(cls._get_filename(key))

    '''
    @brief: remove method
    '''
    @classmethod
    def remove(cls, key):
        return os.remove(cls._get_filename(key))


'''
@brief: REDIS Storage
'''
class RedisStorage(object):

    '''
    @brief: REDIS retry functionality
    '''
    @staticmethod
    def redis_retry(func):
        redis_sleep = int(os.environ.get('REDIS_SLEEP', 5))
        while True:
            try:
                return func()
            except redis.ConnectionError:
                print(f'Server {redis_host} unavailable, retrying in {redis_sleep}...')
                time.sleep(redis_sleep)

    '''
    @brief: get method
    '''
    @classmethod
    def get(cls, key):
        data = cls.redis_retry(lambda: red_conn.get(key))
        if not data:
            raise Exception("No valid pin found")
        return data

    '''
    @brief: set method
    '''
    @classmethod
    def set(cls, key, data):
        return cls.redis_retry(lambda: red_conn.set(key, data))

    '''
    @brief: exists
    '''
    @classmethod
    def exists(cls, key):
        return cls.redis_retry(lambda: red_conn.exists(key))

    '''
    @brief: remove
    '''
    @classmethod
    def remove(cls, key):
        return cls.redis_retry(lambda: red_conn.delete(key))


'''
@brief: get storage
'''
def get_storage():
    if not redis_host:
        print("Using filesystem based storage")
        return FileStorage

    print(f'''Connecting to {redis_host}:{redis_port},
health check every {redis_health_check_interval}''')

    RedisStorage.redis_retry(lambda: red_conn.ping())
    return RedisStorage


'''
@brief: PINDB
'''
class PINDb(object):

    storage = get_storage()

    '''
    @brief: extract fields
    '''
    @classmethod
    def _extract_fields(cls, cke, data):
        assert len(data) == (2*SHA256_LEN) + EC_SIGNATURE_RECOVERABLE_LEN
        
        pin_secret = data[:SHA256_LEN]
        entropy = data[SHA256_LEN: SHA256_LEN + SHA256_LEN]
        sig = data[SHA256_LEN + SHA256_LEN:]

        signed_msg = sha256(cke + pin_secret + entropy)
        client_public_key = ec_sig_to_public_key(signed_msg, sig)

        return pin_secret, entropy, client_public_key

    @classmethod
    def _save_pin_fields(cls, pin_pubkey_hash, hash_pin_secret, aes_key,
                         pin_pubkey, aes_pin_data_key, count=0):

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        count_bytes = struct.pack('B', count)
        plaintext = hash_pin_secret + aes_key + count_bytes
        encrypted = encrypt(storage_aes_key, plaintext)
        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)
        version_bytes = struct.pack('B', VERSION)
        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        cls.storage.set(pin_pubkey_hash, version_bytes + hmac_payload + encrypted)

        return aes_key

    '''
    @brief: load pin fields
    '''
    @classmethod
    def _load_pin_fields(cls, pin_pubkey_hash, pin_pubkey, aes_pin_data_key):

        data = cls.storage.get(pin_pubkey_hash)
        assert len(data) == 129
        version, hmac_received, encrypted = data[:1], data[1:33], data[33:]

        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)
        version_bytes = struct.pack('B', VERSION)
        assert version_bytes == version
        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        assert hmac_payload == hmac_received

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        plaintext = decrypt(storage_aes_key, encrypted)

        assert len(plaintext) == 32 + 32 + 1

        hash_pin_secret, aes_key = plaintext[:32], plaintext[32:64]
        count = struct.unpack('B', plaintext[64: 64 + struct.calcsize('B')])[0]

        return hash_pin_secret, aes_key, count

    '''
    @brief: make aes key[client]
    '''
    @classmethod
    def make_client_aes_key(self, pin_secret, saved_key):
        aes_key = hmac_sha256(saved_key, pin_secret)
        assert len(aes_key) == AES_KEY_LEN_256
        return aes_key

    '''
    @brief: get aes key
    ''' 
    @classmethod
    def get_aes_key_impl(cls, pin_pubkey, pin_secret, aes_pin_data_key):
        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        saved_hps, saved_key, counter = cls._load_pin_fields(pin_pubkey_hash,
                                                             pin_pubkey,
                                                             aes_pin_data_key)

        hash_pin_secret = sha256(pin_secret)
        if compare_digest(saved_hps, hash_pin_secret):
            if counter != 0:
                cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key,
                                     pin_pubkey, aes_pin_data_key)

            return saved_key

        if counter >= 2:
            cls._save_pin_fields(pin_pubkey_hash,
                                 saved_hps,
                                 bytearray(AES_KEY_LEN_256),
                                 pin_pubkey,
                                 aes_pin_data_key)
            cls.storage.remove(pin_pubkey_hash)
            raise Exception("Too many attempts")
        else:
            cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key, pin_pubkey,
                                 aes_pin_data_key, counter + 1)
            raise Exception("Invalid PIN")

    '''
    @brief: get aes key
    '''
    @classmethod
    def get_aes_key(cls, cke, payload, aes_pin_data_key):
        pin_secret, _, pin_pubkey = cls._extract_fields(cke, payload)

        try:
            saved_key = cls.get_aes_key_impl(pin_pubkey,
                                             pin_secret,
                                             aes_pin_data_key)
        except Exception as e:
            saved_key = os.urandom(AES_KEY_LEN_256)

        return cls.make_client_aes_key(pin_secret, saved_key)

    '''
    @brief: set pin
    '''
    @classmethod
    def set_pin(cls, cke, payload, aes_pin_data_key):
        pin_secret, entropy, pin_pubkey = cls._extract_fields(cke, payload)

        our_random = os.urandom(32)
        new_key = hmac_sha256(our_random, entropy)

        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        hash_pin_secret = sha256(pin_secret)
        saved_key = cls._save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key,
                                         pin_pubkey, aes_pin_data_key)

        return cls.make_client_aes_key(pin_secret, saved_key)