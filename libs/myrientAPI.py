#!/usr/bin/env python3
"""myrientAPI

Módulo responsável por buscar e parsear a listagem do Myrient e expor
uma função para registro de rotas Flask. O módulo centraliza toda a
logica relacionada a rota `/gamelist`.

Funcionalidades:
- `get_gamelist(buscar=None)` -> lista de jogos (dicts com title,url,meta)
- `register_routes(app)` -> registra a rota `/gamelist` no Flask app

"""
from __future__ import annotations

import time
import re
import html as _html
import urllib.request
import urllib.parse
from typing import List, Dict, Optional

# URL default fornecida pelo usuário
DEFAULT_LIST_URL = 'https://myrient.erista.me/files/Redump/Sony%20-%20PlayStation%203/'

# cache simples em memória para reduzir número de requisições
_CACHE = {'ts': 0.0, 'data': None}
_CACHE_TTL = 300  # segundos


def _fetch_listing(url: str = DEFAULT_LIST_URL, timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers={'User-Agent': 'myrient-api/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _parse_listing(html_text: str, base_url: str = DEFAULT_LIST_URL) -> List[Dict]:
    """Parseia o HTML de listagem e retorna uma lista de dicts:
    { 'title': ..., 'url': ..., 'meta': ... }

    O parser é tolerante: tenta localizar o <tbody> da tabela e extrair
    cada <tr>. Para cada linha busca o primeiro <a href> como o arquivo
    e coleta as demais colunas como `meta` (unidas por ' | ').
    """
    body_match = re.search(r'<tbody.*?>(.*?)</tbody>', html_text, re.S | re.I)
    container = body_match.group(1) if body_match else html_text

    rows = re.findall(r'<tr.*?>(.*?)</tr>', container, re.S | re.I)
    out: List[Dict] = []

    for row in rows:
        # buscar o link principal
        m = re.search(r'<a\s+href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<title>.*?)</a>', row, re.S | re.I)
        if not m:
            continue
        href = m.group('href').strip()
        title_raw = m.group('title')
        # limpar tags internas e entidades HTML
        title = re.sub(r'<.*?>', '', title_raw).strip()
        title = _html.unescape(title)

        # coletar demais colunas da <tr> como metadados
        tds = re.findall(r'<td.*?>(.*?)</td>', row, re.S | re.I)
        meta_parts = []
        # pular primeiro td que geralmente contém o link
        for td in tds[1:]:
            text = re.sub(r'<.*?>', '', td).strip()
            if text:
                meta_parts.append(_html.unescape(text))

        meta = ' | '.join(meta_parts)

        # construir URL absoluta
        url = urllib.parse.urljoin(base_url, href)
        out.append({'title': title, 'url': url, 'meta': meta})

    return out


def get_gamelist(buscar: Optional[str] = None, use_cache: bool = True) -> List[Dict]:
    """Retorna a lista de jogos. Se `buscar` for informado, filtra os
    resultados pelo termo (case-insensitive) no título.
    """
    now = time.time()
    if use_cache and _CACHE.get('data') is not None and (now - _CACHE.get('ts', 0)) < _CACHE_TTL:
        data = _CACHE['data']
    else:
        html_text = _fetch_listing()
        data = _parse_listing(html_text)
        _CACHE['data'] = data
        _CACHE['ts'] = now

    if buscar:
        term = buscar.lower()
        return [item for item in data if term in (item.get('title') or '').lower()]

    return data


def register_routes(app, base_url: str = DEFAULT_LIST_URL):
    """Registra a rota `/gamelist` no Flask `app` fornecido.

    Rota:
    - GET /gamelist -> retorna JSON com todos os jogos
    - GET /gamelist?buscar=termo -> retorna os jogos cujo título contenha `termo`
    """
    try:
        from flask import jsonify, request
    except Exception:
        raise

    @app.route('/gamelist', methods=['GET'])
    def _gamelist():
        q = request.args.get('buscar')
        try:
            items = get_gamelist(buscar=q)
        except Exception:
            # em caso de erro no fetch/parsing, retornar lista vazia com 502
            return jsonify({'error': 'failed_fetch'}), 502
        return jsonify(items)

    return True
