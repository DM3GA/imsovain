#!/usr/bin/env python3
import datetime

import click
import multiprocessing as mp
import time
import signal
import sys
import os
import nacl.bindings as S
from binascii import hexlify as hx, unhexlify as ux
import struct
import hashlib
import hexdump
import subprocess
import concurrent.futures as conc


class Keys:

    def __init__(self, sk: bytes, pk: bytes) -> None:
        if len(sk) > 32:
            self.sk = sk[:32]
        else:
            self.sk = sk
        self.pk = pk
        self.mpisk = bytes(MPI(self.sk))
        self.mpipk = bytes(MPI(self.pk))

    def __str__(self) -> str:
        return f'SK: {hexdump.dump(self.sk)}\nPK: {hexdump.dump(self.pk[1:])}\n'

    def get_sodium_sk(self) -> bytes:
        return self.sk + self.pk[1:]

    def get_sk(self) -> bytes:
        return self.sk

    def get_pk(self) -> bytes:
        return self.pk

    def get_mpi_pk(self) -> bytes:
        return self.mpipk

    def get_mpi_sk(self) -> bytes:
        return self.mpisk


class MPI:

    def __init__(self, val: bytes) -> None:
        tmp = list(val)
        offset = 0
        for i, __ in enumerate(tmp):
            if tmp[i] == 0:
                continue
            else:
                offset = i
                break

        tmp = tmp[offset:]

        assert tmp[0] != 0

        lz = 0
        while not (tmp[0] << lz) & 0x80:
            lz += 1

        len_bits = len(tmp) * 8 - lz
        self.bytes = struct.pack('>H', len_bits) + bytes(tmp)

    def __bytes__(self) -> bytes:
        return self.bytes

    def __str__(self) -> str:
        return repr(self.bytes)


class SecretKeyPackage:

    def __init__(self, k: Keys, unixtime: int) -> None:
        self.type = b'\x94'
        self.version = b'\x04'
        self.time = struct.pack('>I', unixtime)
        self.key_algo = b'\x16'
        self.curve_oid_and_len = ux('092b06010401da470f01')
        self.k = k
        self.csum = (sum(list(self.k.get_mpi_sk())) % 0xffff).to_bytes(2, 'big')
        self.key_enc = b'\x00'

    def __bytes__(self) -> bytes:
        plen = 1 + 4 + 1 + len(self.curve_oid_and_len) + len(self.get_mpi_pk()) + 1 + len(self.get_mpi_sk()) + 2
        tmp = [self.type, plen.to_bytes(1, 'big'), self.version, self.time, self.key_algo, self.curve_oid_and_len,
               self.get_mpi_pk(), self.key_enc, self.get_mpi_sk(), self.csum]
        return b''.join(tmp)

    def get_body(self) -> bytes:
        tmp = [self.version, self.time, self.key_algo, self.curve_oid_and_len, self.get_mpi_pk()]
        return b''.join(tmp)

    def set_time(self, unixtime: int) -> None:
        self.time = struct.pack('>I', unixtime)

    def get_time(self) -> bytes:
        return self.time

    def fpr(self) -> bytes:
        return hashlib.sha1(self.get_raw_fpr_data()).digest()

    def get_raw_fpr_data(self) -> bytes:
        plen = 1 + 4 + 1 + len(self.curve_oid_and_len) + len(self.get_mpi_pk())
        return b'\x99' + plen.to_bytes(2, 'big') + self.version + self.time + self.key_algo \
                 + self.curve_oid_and_len + self.get_mpi_pk()

    def get_mpi_sk(self) -> bytes:
        return self.k.get_mpi_sk()

    def get_mpi_pk(self) -> bytes:
        return self.k.get_mpi_pk()

    def get_raw_sk(self) -> bytes:
        return self.k.get_sk()

    def get_raw_pk(self) -> bytes:
        return self.k.get_pk()

    def get_sodium_sk(self) -> bytes:
        return self.k.get_sodium_sk()

    @staticmethod
    def key_id_from_fpr(fpr: bytes) -> bytes:
        return fpr[-8:]


class UserIDPackage:

    def __init__(self, s: str) -> None:
        self.s = s.encode()
        self.slen = len(self.s).to_bytes(1, 'big')

    def __bytes__(self) -> bytes:
        return b'\xb4' + self.slen + self.s

    def get_body(self) -> bytes:
        return self.s


class SignaturePacket:

    def __init__(self, skp: SecretKeyPackage, uidp: UserIDPackage) -> None:
        fpr = skp.fpr()

        self.type = b'\x88'
        self.version = b'\x04'
        self.sig_type = b'\x13'  # Self sig
        self.key_algo = b'\x16'  # Ed25519
        self.hash_algo = b'\x08'  # SHA256
        self.hashed_subp = b'\x16\x21' + self.version + fpr + b'\x05\02' + skp.get_time() + \
                           ux(b'021b01040b090a0d0515090a080b051600020301021e01021780')
        self.unhashed_subp = b'\x09\x10' + SecretKeyPackage.key_id_from_fpr(fpr)
        self.skp = skp
        self.uidp = uidp

    def __bytes__(self) -> bytes:
        hashme1 = b'\x99' + len(self.skp.get_body()).to_bytes(2, 'big') + self.skp.get_body() \
                  + b'\xb4' + len(self.uidp.get_body()).to_bytes(4, 'big') + self.uidp.get_body()
        hashme2 = self.version + self.sig_type + self.key_algo + self.hash_algo \
                  + len(self.hashed_subp).to_bytes(2, 'big') + self.hashed_subp
        hashme = hashme1 + hashme2 + b'\x04\xff' + len(hashme2).to_bytes(4, 'big')

        digest = hashlib.sha256(hashme).digest()
        sig = S.crypto_sign(digest, self.skp.get_sodium_sk())[:64]
        rsig = bytes(MPI(sig[:32]))
        ssig = bytes(MPI(sig[32:]))

        plen = 1 + 1 + 1 + 1 + 2 + len(self.hashed_subp) + 2 + len(self.unhashed_subp) + 2 + len(rsig) + len(ssig)

        return self.type + plen.to_bytes(1, 'big') + self.version + self.sig_type + self.key_algo + self.hash_algo \
               + len(self.hashed_subp).to_bytes(2, 'big') + self.hashed_subp \
               + len(self.unhashed_subp).to_bytes(2, 'big') + self.unhashed_subp + digest[:2] + rsig + ssig


def clamp(sk: bytes) -> bytes:
    sk = list(sk)
    sk[0] &= 248
    sk[31] &= 127
    sk[31] |= 64
    return bytes(sk)

def format_fingerprint(fpr: str) -> str:
    return f'{fpr[:-16]}_{fpr[-16:-12]}_{fpr[-12:-8]}_{fpr[-8:-4]}_{fpr[-4:]}' if len(fpr) > 16 else fpr


def found_key(skp: SecretKeyPackage, fpr: str, outdir: str, exit_after_found: bool):
    print(f'\n~> Found key with fingerprint {format_fingerprint(fpr)}')
    uidp = UserIDPackage('Example User <user@example.com>')
    sig = SignaturePacket(skp, uidp)

    fullkey = bytes(skp) + bytes(uidp) + bytes(sig)
    with open(outdir + f'/{format_fingerprint(fpr)}', 'wb') as f:
        f.write(fullkey)
    if exit_after_found:
        os.kill(os.getppid(), signal.SIGINT)


def gen_one_key(max_time_days: int, outdir: str, exit_after_found: bool, accel: str) -> int:

    with open('/dev/urandom', 'rb') as f:
        pk, sk = S.crypto_sign_seed_keypair(f.read(32))
        pk = b'\x40' + pk
    k = Keys(sk, pk)
    # print(f'Worker {int(mp.current_process().name.split("-")[1]):2d}: New key generated:\n{k}')
    unixtime = int(time.time())
    difftime = max_time_days * 24 * 60 * 60

    if accel != '':
        try:
            skp = SecretKeyPackage(k, unixtime)
            sendme = b'\x01' + len(skp.get_raw_fpr_data()).to_bytes(2, 'big') + skp.get_raw_fpr_data() + \
                     b'\x02\x00\x02\x00\x04' + b'\x03\x00\x04' + difftime.to_bytes(4, 'big')

            # hexdump.hexdump(sendme)
            # with open(f'/tmp/foo_foo_{mp.current_process().ident}', 'wb') as f:
            #     f.write(sendme)

            p = subprocess.Popen(accel, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

            start = time.perf_counter()
            pid = p.pid
            print(f'Started worker {pid} at {datetime.datetime.now().replace(microsecond=0)}')
            sys.stdout.write('<')
            sys.stdout.flush()
            

            output = p.communicate(input=sendme)[0]

            curr = time.perf_counter()
            print(f'Worker {pid} -> Ran {difftime} SHA1 computations in {curr - start:4.2f}s. {difftime / (curr - start)} keys/s at {datetime.datetime.now().replace(microsecond=0)}')
            sys.stdout.write('>')
            sys.stdout.flush()

            if int(output.strip().split(b'\n')[0]) == -1:
                # print(f'Nothing found.')
                return -1
            else:
                # good_input = skp.get_raw_fpr_data()[:4] + int(output).to_bytes(4, 'big') + skp.get_raw_fpr_data()[8:]
                # for c in good_input:
                #     print(f'\\x{c:02X}', end='')
                # print()
                # print(int(output))

                skp = SecretKeyPackage(k, int(output))
                fpr = hx(skp.fpr()).decode().upper()

                # if True:
                found_key(skp, fpr, outdir, exit_after_found)
                ret = p.returncode
                p.terminate()
                return ret
                # else:
                #     print(f'Accelerator program returned bogus data. Terminating.')
                #     os.kill(os.getppid(), signal.SIGINT)
                #     mp.current_process().terminate()
        except Exception as e:
            print(f'Something went wrong with the accelerator program. Terminating.\n{e}')
            os.kill(os.getppid(), signal.SIGINT)
            p.terminate()

    else:
        raise NotImplementedError('Need an accelerator')


def sig_handler(sig, frame) -> None:
    sys.exit(0)


def print_accel_help():
    print('''
To generate vanity OpenPGP keys we set the creation date to `now` and then decrement the timestamp until
the hash matches the regex.

The program that will help accelerating the SHA1 brute-force of the key ID receives all the data needed via 
TLV encoding on stdin. It has to output the found time-stamp on its stdout as a positive integer or -1 if no
timestamp could be found so that the SHA1 output matches the regex.

The TLV format is (all data big endian):

    Tags:
        0x01 - The raw data to hash with the timestamp of `now`.
        0x02 - The offset from the start of the raw data to the location of the timestamp in the raw data,
               encoded as uint16_t
        0x03 - The maximum iterations, encoded as uint32_t
        
    Lengths:
        Lengths are always uint16_t, big endian
    
    An example message would be:
    
    01 - The raw to-be-hashed data follows
    
    00 36 - The length is 54 Bytes
    
    99 00 33 04 5E 6B A8 AE  16 09 2B 06 01 04 01 DA - The raw data 
    47 0F 01 01 07 40 AA FA  F9 1B 48 3E 90 7B 59 21
    FA CD C4 6F 8E 7B 2C 07  12 C3 6C E2 0A 6E 33 2C
    33 51 04 B7 57 78
    
    02 - The time offset follows
    
    00 02 - Two Bytes follow
    
    00 04 - Date begins at index 4
    
    03 - Maximum iterations
    
    00 04 - Four byte follow
    
    00 09 3a 80 - 7 days in seconds ( 7 * 24 * 60 * 60 = 604800 = 0x93a80 )
''')


@click.command()
@click.option('--threads', '-t', type=int, default=mp.cpu_count(), required=False,
              help='How many threads to run in parallel. Defaults to the number of CPUs in the system.')
@click.option('--outdir', '-o', type=click.Path(), required=True, help='Save keys to this database')
@click.option('--max-time-days', '-m', type=int, default=365, help='How long in the past do we search for matching keys')
@click.option('--exit-after-found', '-x', is_flag=True, default=False,
              help='Quit after the first matching key is found?')
@click.option('--accelerate-with', '-a', type=str, required=True, default='',
              help='Accelerate SHA1 fingerprint calculation with this external binary. '
                   'For more information pass /dev/null to this option')
def pgpgen(threads: int, outdir: click.Path, max_time_days: int, exit_after_found: bool,
           accelerate_with: str) -> None:

    outdir = os.path.abspath(click.format_filename(str(outdir)))

    if accelerate_with == '/dev/null':
        print_accel_help()
        sys.exit(0)
    elif accelerate_with != '':
        if not os.path.isfile(accelerate_with):
            print(f'Accelerator {accelerate_with} does not exist.')
            sys.exit(1)

    if not os.path.exists(outdir):
        os.mkdir(outdir)
    else:
        if not os.path.isdir(outdir):
            raise IOError(f'Path {outdir} is not a directory')
    while True:
        try:
            print(f'ITER {str(datetime.datetime.now()).split(".")[0]}')
            with mp.Pool(threads) as pool:
                for i in range(256*threads):
                    pool.apply_async(gen_one_key, (max_time_days, outdir, exit_after_found, accelerate_with))
                pool.close()
                pool.join()
        except Exception:
            pass

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

if __name__ == '__main__':
    pgpgen()
