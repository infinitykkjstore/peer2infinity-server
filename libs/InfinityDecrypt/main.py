import os
import sys
import time
import threading
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from binascii import unhexlify
import mmap
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor

SECTOR_SIZE = 2048
DEFAULT_CHUNK_BYTES = 512 * 1024 * 1024  # 512 MiB (bigger chunks reduce overhead)
THREAD_COUNT = max(1, os.cpu_count() or 4)

try:
    from Crypto.Cipher import AES
except Exception:
    print("Missing dependency: pycryptodome is required. Install with: pip install pycryptodome")
    raise


def read_key_file(path: Path) -> bytes:
    data = path.read_bytes()
    # decode as ascii-ish and keep only hex characters (0-9A-Fa-f)
    try:
        s = data.decode('ascii', errors='ignore')
    except Exception:
        s = ''.join(chr(b) for b in data)
    import re
    s2 = re.sub(r'[^0-9A-Fa-f]', '', s)
    if len(s2) != 32:
        raise ValueError(f"Expected 32 hex chars in key file, got {len(s2)}")
    try:
        key = unhexlify(s2)
    except Exception as e:
        raise ValueError(f"Failed to decode hex key: {e}")
    if len(key) != 16:
        raise ValueError("Decoded key must be 16 bytes")
    return key


def extract_regions(fp) -> list:
    # Read first 4096 bytes and parse exactly like the Rust implementation (requires full header)
    fp.seek(0)
    header = fp.read(4096)
    if len(header) != 4096:
        raise ValueError("Failed to read 4096-byte header required to extract regions")
    num_normal_regions = int.from_bytes(header[0:4], byteorder='big')
    regions_count = (num_normal_regions * 2) - 1
    regions = []
    for i in range(regions_count):
        offset = 4 + i * 8
        # Rust implementation assumes header is long enough; mirror that behavior and raise on malformed header
        if offset + 8 > len(header):
            raise ValueError("Malformed header when extracting regions")
        start_sector = int.from_bytes(header[offset:offset+4], byteorder='big')
        end_sector = int.from_bytes(header[offset+4:offset+8], byteorder='big')
        regions.append((start_sector, end_sector))
    return regions


def is_encrypted(regions, sector_idx: int, sector_data: bytes) -> bool:
    if all(b == 0 for b in sector_data):
        return False
    for start, end in regions:
        if sector_idx >= start and sector_idx < end:
            return True
    return False


def generate_iv(sector: int) -> bytes:
    iv = bytearray(16)
    iv[12] = (sector >> 24) & 0xFF
    iv[13] = (sector >> 16) & 0xFF
    iv[14] = (sector >> 8) & 0xFF
    iv[15] = sector & 0xFF
    return bytes(iv)


def decrypt_sector_ecb_xor(key: bytes, sector_bytes: bytes, sector_index: int) -> bytes:
    """Decrypt a single sector using AES-ECB then XOR each decrypted block with prev (prev=IV then previous ciphertext block).

    Returns decrypted bytes for the sector.
    """
    # decrypt entire sector at once (ECB) to minimize C<->Python overhead
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(sector_bytes)
    out = bytearray(SECTOR_SIZE)
    iv = generate_iv(sector_index)
    prev = iv
    # process 16-byte blocks
    for i in range(0, SECTOR_SIZE, 16):
        db = dec[i:i+16]
        # XOR decrypted block with prev (fast C implementation)
        xb = strxor(db, prev)
        out[i:i+16] = xb
        # update prev to ciphertext block (original sector bytes)
        prev = sector_bytes[i:i+16]
    return bytes(out)


def process_chunk(start_sector: int, end_sector: int, iso_path: str, out_path: str, key: bytes, regions) -> int:
    """Process a range of sectors [start_sector, end_sector) reading from iso_path and
    writing decrypted data to out_path. Returns number of sectors processed.
    This function is safe to run in a separate process (no shared-memory writes).
    """
    total_sectors = end_sector - start_sector
    start_offset = start_sector * SECTOR_SIZE
    read_size = total_sectors * SECTOR_SIZE

    with open(iso_path, 'rb') as inf, open(out_path, 'r+b') as outf:
        iso_mm = mmap.mmap(inf.fileno(), 0, access=mmap.ACCESS_READ)
        out_mm = mmap.mmap(outf.fileno(), 0)
        processed = 0
        for i in range(total_sectors):
            sector_idx = start_sector + i
            off = start_offset + i * SECTOR_SIZE
            sector = iso_mm[off:off + SECTOR_SIZE]
            if not is_encrypted(regions, sector_idx, sector):
                # copy original sector unchanged
                out_mm[off:off + SECTOR_SIZE] = sector
                processed += 1
                continue
            # decrypt sector using ECB+XOR per-block (matches ps3dec)
            dec = decrypt_sector_ecb_xor(key, sector, sector_idx)
            # write decrypted bytes
            out_mm[off:off + SECTOR_SIZE] = dec
            processed += 1

        out_mm.flush()
        iso_mm.close()
        out_mm.close()
    return processed


def decrypt_iso(iso_path: Path, dkey_path: Path, out_iso_path: Path, *, threads: int = THREAD_COUNT, chunk_bytes: int = DEFAULT_CHUNK_BYTES, progress_cb=None):
    """Decrypts `iso_path` using the `dkey_path` and writes output to `out_iso_path`.

    progress_cb(progress_percent: int) can be provided to receive progress updates (0-100).
    """
    start_time = time.time()

    if not iso_path.exists():
        raise FileNotFoundError(f"ISO not found: {iso_path}")
    if not dkey_path.exists():
        raise FileNotFoundError(f"DKEY not found: {dkey_path}")

    key = read_key_file(dkey_path)

    total_size = iso_path.stat().st_size
    if total_size % SECTOR_SIZE != 0:
        raise ValueError("Input size is not a multiple of SECTOR_SIZE")
    total_sectors = total_size // SECTOR_SIZE

    out_iso_path.parent.mkdir(parents=True, exist_ok=True)
    # Prepare output file with same size
    with out_iso_path.open('wb') as f:
        f.truncate(total_size)

    # extract regions
    with iso_path.open('rb') as f:
        regions = extract_regions(f)

    chunk_sectors = max(1, chunk_bytes // SECTOR_SIZE)
    tasks = []
    s = 0
    while s < total_sectors:
        e = min(total_sectors, s + chunk_sectors)
        tasks.append((s, e))
        s = e

    # use ProcessPoolExecutor for real parallelism
    futures = []
    total_processed = 0
    remaining = []
    with ProcessPoolExecutor(max_workers=threads) as ex:
        for a, b in tasks:
            futures.append(ex.submit(process_chunk, a, b, str(iso_path), str(out_iso_path), key, regions))
        remaining = list(futures)
        last_report = 0
        while remaining:
            # collect finished futures
            for f in list(remaining):
                if f.done():
                    try:
                        res = f.result()
                        total_processed += int(res or 0)
                    except Exception:
                        # if a child failed, reraise to stop
                        raise
                    remaining.remove(f)
            percent = int((total_processed / total_sectors) * 100) if total_sectors else 100
            now = time.time()
            if progress_cb and (now - last_report >= 1):
                try:
                    progress_cb(percent)
                except Exception:
                    pass
                last_report = now
            time.sleep(0.2)

    # final report
    if progress_cb:
        try:
            progress_cb(100)
        except Exception:
            pass

    elapsed = time.time() - start_time
    return out_iso_path


if __name__ == '__main__':
    # preserve CLI for backward compatibility
    if len(sys.argv) < 3:
        print("Usage: InfinityDecrypt/main.py <iso_path> <dkey_path> [out_dir]")
        sys.exit(2)
    iso_path = Path(sys.argv[1])
    dkey_path = Path(sys.argv[2])
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path('out')
    out_dir.mkdir(parents=True, exist_ok=True)
    out_iso = out_dir / f"{iso_path.stem}_decrypted.iso"
    print('Starting decrypt...')
    def _cb(p):
        print(f'Decrypt progress: {p}%')
    decrypt_iso(iso_path, dkey_path, out_iso, progress_cb=_cb)
    print('Done:', out_iso)
