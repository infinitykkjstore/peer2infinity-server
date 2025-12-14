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
CLOUDFLARED_LOG = os.path.join(tempfile.gettempdir(), 'cloudflared_announce.log')


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


def start_cloudflared_detached(cf_exec, timeout=30):
	safe = shlex.quote(cf_exec)
	cmd = f"nohup {safe} tunnel --url localhost:8081 > {CLOUDFLARED_LOG} 2>&1 & echo $!"
	try:
		out = subprocess.check_output(cmd, shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)
		pid = int(out.decode().strip())
	except Exception as e:
		print('Erro ao iniciar cloudflared (detached):', e)
		return None, None

	# Após iniciar, detectar PID real do processo (o nohup/encapsulador pode
	# devolver o PID do shell; então buscamos o processo 'cloudflared' ativo
	# que contenha o argumento '--url localhost:8081' e preferimos esse PID.
	def _find_running_cf(pid_hint=None):
		try:
			out = subprocess.check_output(['ps', '-eo', 'pid,args'], text=True)
		except Exception:
			return None
		best = None
		for line in out.splitlines():
			parts = line.strip().split(None, 1)
			if len(parts) < 2:
				continue
			try:
				p = int(parts[0])
			except Exception:
				continue
			args = parts[1]
			if 'cloudflared' in args and '--url localhost:8081' in args:
				# prefer the hinted pid if match
				if pid_hint and p == pid_hint:
					return p
				best = p
		return best

	real_pid = _find_running_cf(pid_hint=pid)
	if real_pid:
		pid = real_pid

	# esperar o log para obter a linha com trycloudflare URL (espera maior)
	deadline = time.time() + max(timeout, 60)
	domain = None
	pattern = re.compile(r'https?://[^\s]+trycloudflare\.com[^\s]*')
	last_size = 0
	while time.time() < deadline:
		try:
			if os.path.exists(CLOUDFLARED_LOG):
				# ler apenas o novo conteúdo para eficiência
				with open(CLOUDFLARED_LOG, 'r', errors='ignore') as lf:
					lf.seek(0, os.SEEK_END)
					size = lf.tell()
					# se arquivo encolheu, re-ler tudo
					if size < last_size:
						lf.seek(0)
					else:
						lf.seek(max(0, size - 16384))
					data = lf.read()
					last_size = size
					m = pattern.search(data)
					if m:
						domain = _clean_ansi_and_control(m.group(0))
						break
		except Exception:
			pass
		time.sleep(0.5)

	return pid, domain


def download_cloudflared(dest_path):
	url = 'http://infinitykkj.shop/auth/svrgoat/libs/cloudflared'
	print(f'Tentando baixar cloudflared para {dest_path}... (rodando apt update)')
	try:
		subprocess.run(['apt', 'update'], check=False)
	except Exception:
		pass

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
		print('Falha ao baixar cloudflared:', e)
		return False


def ensure_cloudflared():
	# Verifica estado salvo
	state = read_state()
	pid = state.get('cloudflared_pid')
	domain = state.get('cloudflared_url')

	# Se o PID salvo estiver vivo e já tivermos domínio, retornar
	if pid and domain and is_pid_alive(pid):
		return domain

	# Se PID salvo está vivo mas domínio ausente, tentar extrair do log
	if pid and is_pid_alive(pid) and not domain:
		try:
			if os.path.exists(CLOUDFLARED_LOG):
				with open(CLOUDFLARED_LOG, 'r', errors='ignore') as lf:
					data = lf.read()
					m = re.search(r'https?://[^\s]+trycloudflare\.com[^\s]*', data)
					if m:
						domain = _clean_ansi_and_control(m.group(0))
						state.update({'cloudflared_url': domain})
						write_state(state)
						return domain
		except Exception:
			pass


	# detecta binário
	cf_exec = shutil.which('cloudflared')
	if not cf_exec:
		local_exec = os.path.join(os.getcwd(), 'cloudflared')
		if os.path.isfile(local_exec) and os.access(local_exec, os.X_OK):
			cf_exec = local_exec

	# se não encontrado, tenta baixar para ./cloudflared
	if not cf_exec:
		local_exec = os.path.join(os.getcwd(), 'cloudflared')
		ok = download_cloudflared(local_exec)
		if not ok:
			# antes de falhar, tentar detectar se já existe um processo cloudflared
			try:
				out = subprocess.check_output(['ps', '-eo', 'pid,args'], text=True)
				for line in out.splitlines():
					if 'cloudflared' in line and '--url localhost:8081' in line:
						parts = line.strip().split(None, 1)
						try:
							maybe_pid = int(parts[0])
							if is_pid_alive(maybe_pid):
								# tentar extrair domínio do log
								pid = maybe_pid
								break
						except Exception:
							continue
			except Exception:
				pass
			if not cf_exec and not pid:
				return None
		cf_exec = local_exec if os.path.isfile(local_exec) and os.access(local_exec, os.X_OK) else cf_exec

	pid, domain = start_cloudflared_detached(cf_exec, timeout=30)
	if pid is None:
		return None

	# salvar estado
	try:
		state = read_state()
		state.update({'cloudflared_pid': pid, 'cloudflared_url': domain, 'cloudflared_exec': cf_exec, 'cloudflared_started_at': int(time.time())})
		write_state(state)
	except Exception:
		pass

	return domain


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

	# registrar rotas adicionais fornecidas pelos módulos em ./libs (se existirem)
	try:
		from libs import myrientAPI
		try:
			myrientAPI.register_routes(app)
		except Exception as e:
			print('Aviso: falha ao registrar rotas do myrientAPI:', e)
	except Exception:
		pass

	try:
		from libs import dlmanagerAPI
		try:
			dlmanagerAPI.register_routes(app)
		except Exception as e:
			print('Aviso: falha ao registrar rotas do dlmanagerAPI:', e)
	except Exception:
		pass

	def run_app():
		# roda o flask no thread separado
		app.run(host='0.0.0.0', port=8081, threaded=True)

	t = threading.Thread(target=run_app, daemon=True)
	t.start()
	FLASK_STARTED = True
	print('Flask server iniciado na porta 8081')
	return True


def announce(url, ip, ssh_link=None, domain=None, timeout=10, retries=3):
	params = {'ip': ip}
	if ssh_link:
		params['ssh'] = ssh_link
	if domain:
		params['domain'] = domain
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

			# garantir sshx/tmate e obter link (se possível)
			ssh_link = None
			try:
				ssh_link = ensure_sshx()
			except Exception as e:
				print(f"[{now}] erro ao garantir sshx: {e}")

			# garantir cloudflared e obter domínio público (trycloudflare)
			domain = None
			try:
				domain = ensure_cloudflared()
			except Exception as e:
				print(f"[{now}] erro ao garantir cloudflared: {e}")

			ok, resp = announce(url, ip, ssh_link, domain)
			if ok:
				print(f"[{now}] enviado ip={ip} ssh={ssh_link} domain={domain} -> OK; resposta curta: {resp[:200]}")
			else:
				# log e continuar (não encerrar)
				print(f"[{now}] announce falhou para ip={ip} ssh={ssh_link} domain={domain}: {resp}")

		except KeyboardInterrupt:
			raise
		except Exception as e:
			# proteger loop contra qualquer exceção inesperada
			print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Erro inesperado no loop: {e}")

		# Espera 60 segundos antes do próximo envio
		time.sleep(60)


if __name__ == '__main__':
	main()

