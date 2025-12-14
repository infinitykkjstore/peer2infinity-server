#!/usr/bin/env python3
"""dlmanagerAPI

Responsável por criar/gerenciar tasks de download via Flask routes:
- GET /create_task?url=<file_url>
- GET /download?file=<filename>

Fluxo:
1. Recebe URL do zip -> gera task_id -> chama create_task.php para cadastrar
2. Inicia processamento em background: escolhe partição com mais espaço
   cria <mount>/infinity/tmp/<task_id>/, baixa zip, atualiza percentuais via
   update_task.php a cada 5s, extrai zip (mostrando progresso), encontra ISO
   e atualiza status para ready com return_url "/download?file=<iso>".

Implementação com urllib e zipfile para evitar dependências extras.
"""
from __future__ import annotations

import os
import re
import time
import uuid
import json
import socket
import shutil
import threading
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional, Dict
import zipfile
import urllib.parse as _urlparse
import subprocess
import select
import importlib.util
from pathlib import Path

# Endpoints PHP (corrige barras invertidas)
CREATE_TASK_URL = r'http://infinitykkj.shop\auth\svrgoat/apis/create_task.php'.replace('\\', '/')
UPDATE_TASK_URL = r'http://infinitykkj.shop\auth\svrgoat/apis/update_task.php'.replace('\\', '/')

# Map para servir arquivos: filename -> fullpath
_SERVE_MAP: Dict[str, str] = {}
_SERVE_LOCK = threading.Lock()


def _log(*args, **kwargs):
    print('[dlmanager]', *args, **kwargs)


def get_host_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def _choose_best_mount() -> Optional[str]:
    """Executa `df -BG` e escolhe a montagem com maior espaço disponível.
    Retorna o caminho do mount point (ex: /mnt/data) ou None.
    """
    try:
        out = subprocess_check(['df', '-BG', '--output=avail,target'])
    except Exception:
        # fallback: usar /tmp
        return '/tmp'

    best = None
    best_g = -1
    for line in out.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        avail = parts[0]
        target = parts[1]
        # remover o sufixo 'G' e converter
        m = re.match(r'(\d+)(G)?', avail)
        if not m:
            continue
        g = int(m.group(1))
        # ignorar mounts que claramente não são lugares para armazenar
        if target.startswith('/proc') or target.startswith('/sys') or target.startswith('/dev'):
            continue
        if g > best_g:
            best_g = g
            best = target
    return best or '/tmp'


def subprocess_check(cmd):
    import subprocess
    out = subprocess.check_output(cmd, text=True)
    return out


def _call_create_task(task):
    """Chama a API create_task.php com os dados da task (GET)."""
    params = {
        'task_id': task['task_id'],
        'task_type': task.get('task_type', 'download'),
        'host_ip': task.get('host_ip', get_host_ip()),
        'source_url': task.get('source_url', ''),
        'dest_path': task.get('dest_path', ''),
        'download_percentage': task.get('download_percentage', '0%'),
        'unzip_status': task.get('unzip_status', 'waiting'),
        'decrypt_status': task.get('decrypt_status', 'waiting'),
        'return_url': task.get('return_url', ''),
        'status': task.get('status', 'started')
    }
    qs = urllib.parse.urlencode(params)
    full = f"{CREATE_TASK_URL}?{qs}"
    try:
        req = urllib.request.Request(full, headers={'User-Agent': 'dlmanager/1.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode('utf-8', errors='replace')
            _log('create_task response:', data)
            return True
    except Exception as e:
        _log('create_task failed:', e)
        return False


def _call_update_task(task_id: str, key: str, value: str):
    params = {'task_id': task_id, 'key': key, 'value': value}
    qs = urllib.parse.urlencode(params)
    full = f"{UPDATE_TASK_URL}?{qs}"
    try:
        req = urllib.request.Request(full, headers={'User-Agent': 'dlmanager/1.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode('utf-8', errors='replace')
            _log(f'update_task {task_id} {key}={value} ->', data)
            return True
    except Exception as e:
        _log('update_task failed:', e)
        return False


def _download_with_progress(url: str, dest_path: str, task_id: str):
    # Streaming download com acompanhamento por tamanho
    tmp_path = dest_path + '.down'
    # sanitizar/escape da URL para suportar espaços e caracteres especiais
    def _sanitize_url(u: str) -> str:
        try:
            parts = _urlparse.urlsplit(u)
            # quote path, preservando '/' e '%' (para não duplamente-encode)
            path = _urlparse.quote(parts.path, safe="/%")
            # quote query preservando =&%/ (mantém parâmetros existentes)
            query = _urlparse.quote(parts.query, safe="=&%")
            return _urlparse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
        except Exception:
            return u

    safe_url = _sanitize_url(url)

    # Use wget for robust download and parse its stderr for progress
    cmd = [
        'wget', '--content-disposition', '--trust-server-names',
        '--progress=bar:force', safe_url, '-O', dest_path
    ]

    _log('running:', ' '.join(cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        _log('failed to start wget:', e)
        _call_update_task(task_id, 'status', 'error')
        return False

    last_update = time.time()
    last_pct = None
    buf = ''
    total = None

    # read stderr in real time using select
    stderr = proc.stderr
    fd = stderr.fileno()
    while True:
        rlist, _, _ = select.select([fd], [], [], 1.0)
        if rlist:
            chunk = stderr.read(4096)
            if not chunk:
                # EOF
                break
            buf += chunk
            # extract Length: <bytes>
            mlen = re.search(r'Length:\s*(\d+)', buf)
            if mlen:
                try:
                    total = int(mlen.group(1))
                except Exception:
                    total = None
            # find all percent occurrences and take last
            percents = re.findall(r'(\d{1,3})%', buf)
            if percents:
                pct = int(percents[-1])
                now = time.time()
                if pct != last_pct or (now - last_update) >= 5:
                    _call_update_task(task_id, 'download_percentage', f"{pct}%")
                    _call_update_task(task_id, 'status', 'downloading')
                    last_pct = pct
                    last_update = now
        # check if process finished
        if proc.poll() is not None:
            # read remaining stderr
            try:
                remaining = stderr.read()
                if remaining:
                    buf += remaining
            except Exception:
                pass
            break

    rc = proc.wait()
    if rc == 0:
        _call_update_task(task_id, 'download_percentage', '100%')
        _call_update_task(task_id, 'status', 'unzipping')
        return True
    else:
        _log('wget failed, rc=', rc)
        try:
            if os.path.exists(dest_path):
                os.remove(dest_path)
        except Exception:
            pass
        _call_update_task(task_id, 'status', 'error')
        return False


def _download_quiet(url: str, dest_path: str) -> bool:
    """Baixa sem reporting (usado para dkey). Usa wget/curl silencioso."""
    # sanitize like above
    def _sanitize(u: str) -> str:
        try:
            parts = _urlparse.urlsplit(u)
            path = _urlparse.quote(parts.path, safe="/%")
            query = _urlparse.quote(parts.query, safe="=&%")
            return _urlparse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
        except Exception:
            return u

    safe = _sanitize(url)
    # try wget
    cmd = ['wget', '-q', '--show-progress', '--content-disposition', '--trust-server-names', safe, '-O', dest_path]
    try:
        subprocess.run(cmd, check=True)
        return True
    except Exception:
        # fallback curl
        try:
            subprocess.run(['curl', '-sS', '-L', '-o', dest_path, safe], check=True)
            return True
        except Exception:
            return False


def _download_and_extract_dkey(source_url: str, dest_dir: str) -> Optional[str]:
    """Given the source ZIP URL, attempts to build the corresponding dkey zip URL,
    download it into dest_dir, extract and return path to .dkey file or None."""
    try:
        sp = _urlparse.urlsplit(source_url)
        raw_path = _urlparse.unquote(sp.path)
        dirname = os.path.dirname(raw_path)  # e.g. /files/Redump/Sony - PlayStation 3
        base_name = os.path.basename(dirname)
        # create new dirname with " - Disc Keys TXT" appended
        new_base = base_name + ' - Disc Keys TXT'
        parent = os.path.dirname(dirname)
        new_dir = os.path.join(parent, new_base)
        fname = os.path.basename(raw_path)
        new_path = os.path.join(new_dir, fname)
        # quote path portions
        quoted = '/'.join(_urlparse.quote(p) for p in new_path.split('/'))
        dkey_url = _urlparse.urlunsplit((sp.scheme, sp.netloc, quoted, '', ''))
    except Exception:
        return None

    dkey_zip = os.path.join(dest_dir, 'dkey.zip')
    ok = _download_quiet(dkey_url, dkey_zip)
    if not ok:
        return None

    try:
        with zipfile.ZipFile(dkey_zip, 'r') as zf:
            zf.extractall(path=dest_dir)
    except Exception:
        try:
            os.remove(dkey_zip)
        except Exception:
            pass
        return None

    # find .dkey
    dkey_path = None
    for root, _, files in os.walk(dest_dir):
        for f in files:
            if f.lower().endswith('.dkey'):
                dkey_path = os.path.join(root, f)
                break
        if dkey_path:
            break

    try:
        os.remove(dkey_zip)
    except Exception:
        pass

    return dkey_path


def _extract_zip_progress(zip_path: str, dest_dir: str, task_id: str):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            infos = zf.infolist()
            total = sum(i.file_size for i in infos)
            if total == 0:
                total = None
            extracted = 0
            last_update = time.time()
            for info in infos:
                zf.extract(info, path=dest_dir)
                extracted += info.file_size
                now = time.time()
                if now - last_update >= 5:
                    pct = f"{int((extracted / total) * 100) if total else 0}%"
                    _call_update_task(task_id, 'unzip_status', pct)
                    _call_update_task(task_id, 'status', 'unzipping')
                    last_update = now
            # final
            _call_update_task(task_id, 'unzip_status', 'done')
            _call_update_task(task_id, 'status', 'ready')
            return True
    except Exception as e:
        _log('unzip error:', e)
        _call_update_task(task_id, 'status', 'error')
        return False


def _find_iso_in_dir(d: str) -> Optional[str]:
    for root, _, files in os.walk(d):
        for f in files:
            if f.lower().endswith('.iso'):
                return os.path.join(root, f)
    return None


def _register_servable(file_path: str):
    name = os.path.basename(file_path)
    with _SERVE_LOCK:
        _SERVE_MAP[name] = file_path
    return name


def _task_worker(task_id: str, source_url: str, host_ip: str):
    _log('task worker start', task_id)
    # escolher mount
    mount = _choose_best_mount() or '/tmp'
    base = os.path.join(mount, 'infinity', 'tmp', task_id)
    os.makedirs(base, exist_ok=True)
    dest_zip = os.path.join(base, 'download.zip')

    # tentar baixar/extrair o dkey correspondente antes do download da ISO
    dkey_path = None
    try:
        dkey_path = _download_and_extract_dkey(source_url, base)
        if dkey_path:
            _log('found dkey for', task_id, '->', dkey_path)
            # do not report dkey fetching in update_task per user's request
        else:
            _log('no dkey found for', task_id)
            # update decrypt_status to waiting/missing
            _call_update_task(task_id, 'decrypt_status', 'missing')
    except Exception as e:
        _log('dkey retrieval error:', e)
        _call_update_task(task_id, 'decrypt_status', 'error')

    # atualizar create_task dest_path para o mount base
    _call_update_task(task_id, 'dest_path', base)

    # realizar download
    ok = _download_with_progress(source_url, dest_zip, task_id)
    if not ok:
        _log('download failed for', task_id)
        return

    # extrair zip
    ok = _extract_zip_progress(dest_zip, base, task_id)
    if not ok:
        _log('unzip failed for', task_id)
        return

    # remover zip
    try:
        os.remove(dest_zip)
    except Exception:
        pass

    # localizar iso
    iso = _find_iso_in_dir(base)
    if not iso:
        _log('no iso found in', base)
        _call_update_task(task_id, 'status', 'error')
        return

    # se temos dkey, realizar processo de decrypt usando o módulo InfinityDecrypt
    decrypted_iso_path = None
    if dkey_path:
        try:
            # carregar módulo a partir do arquivo main.py do InfinityDecrypt
            inf_path = os.path.join(os.path.dirname(__file__), 'InfinityDecrypt', 'main.py')
            if os.path.exists(inf_path):
                # load module under package-style name so multiprocessing can import it
                mod_name = 'libs.InfinityDecrypt.main'
                spec = importlib.util.spec_from_file_location(mod_name, inf_path)
                mod = importlib.util.module_from_spec(spec)
                # register in sys.modules so child processes can import by name
                import sys as _sys
                _sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)

                # preparar output name
                iso_basename = os.path.basename(iso)
                out_name = f"{os.path.splitext(iso_basename)[0]}_decrypted_by_infinitykkj.ISO"
                out_path = os.path.join(os.path.dirname(iso), out_name)

                # progress callback
                def _decrypt_progress(pct: int):
                    try:
                        _call_update_task(task_id, 'decrypt_status', f"{int(pct)}%")
                        _call_update_task(task_id, 'status', 'decrypting')
                    except Exception:
                        pass

                _call_update_task(task_id, 'decrypt_status', 'starting')
                # chamar a função decrypt_iso (pode usar multiprocessing internamente)
                try:
                    mod.decrypt_iso(Path(iso), Path(dkey_path), Path(out_path), progress_cb=_decrypt_progress)
                except Exception as e:
                    _log('decrypt raised exception:', e)
                    raise
                # após sucesso, marcar done
                _call_update_task(task_id, 'decrypt_status', 'done')
                # remover iso original criptografado
                try:
                    os.remove(iso)
                except Exception:
                    pass
                decrypted_iso_path = out_path
            else:
                _log('InfinityDecrypt main.py not found at', inf_path)
        except Exception as e:
            _log('decrypt error:', e)
            _call_update_task(task_id, 'decrypt_status', 'error')

    # decidir qual arquivo servir: decrypted if available else original iso
    serve_file = decrypted_iso_path if decrypted_iso_path else iso

    # registrar rota de download (nome público)
    name = _register_servable(serve_file)
    return_url = f"/download?file={urllib.parse.quote(name)}"
    _call_update_task(task_id, 'return_url', return_url)
    _call_update_task(task_id, 'status', 'ready')
    _log('task ready', task_id, '->', return_url)


def register_routes(app):
    from flask import jsonify, request, send_file

    @app.route('/create_task', methods=['GET'])
    def _create_task():
        src = request.args.get('url')
        if not src:
            return jsonify({'error': 'missing url'}), 400

        # gerar task_id
        task_id = uuid.uuid4().hex
        host_ip = get_host_ip()

        # preparar payload para create_task.php
        task = {
            'task_id': task_id,
            'task_type': 'download',
            'host_ip': host_ip,
            'source_url': src,
            'dest_path': '',
            'download_percentage': '0%',
            'unzip_status': 'waiting',
            'decrypt_status': 'waiting',
            'return_url': '',
            'status': 'started'
        }

        created = _call_create_task(task)
        if not created:
            return jsonify({'error': 'create_task_failed'}), 500

        # iniciar processamento em background
        t = threading.Thread(target=_task_worker, args=(task_id, src, host_ip), daemon=True)
        t.start()

        return jsonify({'result': 'accepted', 'task_id': task_id})

    @app.route('/download', methods=['GET'])
    def _download():
        fname = request.args.get('file')
        if not fname:
            return jsonify({'error': 'missing file'}), 400
        fname = urllib.parse.unquote(fname)
        with _SERVE_LOCK:
            path = _SERVE_MAP.get(fname)
        if not path or not os.path.isfile(path):
            return jsonify({'error': 'file_not_found'}), 404
        try:
            return send_file(path, as_attachment=True)
        except Exception as e:
            _log('send_file error:', e)
            return jsonify({'error': 'send_failed'}), 500

    return True
