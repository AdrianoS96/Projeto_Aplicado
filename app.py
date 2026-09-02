"""
Aplicação Principal - Portal Turístico de Maceió (Secure by Design)
Implementa mitigações ativas para o OWASP Top 10:2025:
- A01:2025 (Broken Access Control): Decorador @login_required, validação estrita no servidor.
- A03:2025 (Injection): Consultas SQL parametrizadas e escape de contexto XSS.
- A07:2025 (Identification and Authentication Failures): Hashing seguro, rate-limiting contra força bruta,
  proteção contra enumeração e gestão segura de sessões.
- Proteção Integrada Anti-CSRF e Headers de Segurança HTTP.
"""

import time
import secrets
from functools import wraps
from typing import Dict, List, Tuple
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    make_response,
    Response,
)
from werkzeug.security import check_password_hash
from config import Config
from database import (
    get_active_tourist_spots,
    get_all_tourist_spots,
    get_spot_by_id,
    toggle_spot_visibility,
    get_user_by_username,
)
from seed_data import seed_database

app = Flask(__name__)
app.config.from_object(Config)

# ----------------------------------------------------------------------
# Rate Limiting em Memória para Login (OWASP A07: Brute Force Protection)
# ----------------------------------------------------------------------
# Estrutura: { ip_address: [timestamp_tentativa_1, timestamp_tentativa_2, ...] }
_login_attempts: Dict[str, List[float]] = {}

def is_rate_limited(client_ip: str) -> Tuple[bool, int]:
    """
    Verifica se o endereço IP excedeu o número máximo de tentativas de login.
    Retorna (True, tempo_restante_segundos) se bloqueado, ou (False, 0).
    """
    now = time.time()
    window = Config.LOGIN_ATTEMPT_WINDOW_SECONDS
    max_attempts = Config.MAX_LOGIN_ATTEMPTS
    
    attempts = _login_attempts.get(client_ip, [])
    # Filtra apenas tentativas dentro da janela recente
    valid_attempts = [t for t in attempts if now - t < window]
    _login_attempts[client_ip] = valid_attempts
    
    if len(valid_attempts) >= max_attempts:
        oldest_attempt = valid_attempts[0]
        retry_after = int(window - (now - oldest_attempt))
        return True, max(retry_after, 1)
    
    return False, 0

def record_failed_attempt(client_ip: str) -> None:
    """Registra uma falha de autenticação para o IP do cliente."""
    now = time.time()
    if client_ip not in _login_attempts:
        _login_attempts[client_ip] = []
    _login_attempts[client_ip].append(now)

def reset_attempts(client_ip: str) -> None:
    """Limpa o histórico de tentativas do IP após login bem-sucedido."""
    if client_ip in _login_attempts:
        del _login_attempts[client_ip]

# ----------------------------------------------------------------------
# Gerenciamento de Tokens Anti-CSRF
# ----------------------------------------------------------------------

def get_or_create_csrf_token() -> str:
    """Gera ou recupera o token CSRF armazenado na sessão do usuário."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

@app.context_processor
def inject_csrf_token():
    """Injeta a variável csrf_token globalmente em todos os templates Jinja2."""
    return {"csrf_token": get_or_create_csrf_token()}

@app.before_request
def verify_csrf_token():
    """
    Valida o token CSRF em todas as requisições que alteram estado (POST, PUT, DELETE, PATCH).
    Bloqueia ataques de falsificação de requisições cross-site.
    """
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        session_token = session.get("_csrf_token")
        # Aceita o token no formulário ou no header X-CSRF-Token
        request_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        
        if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
            abort(403, description="Falha na validação do token CSRF. Requisição rejeitada por segurança.")

# ----------------------------------------------------------------------
# Cabeçalhos de Segurança HTTP (OWASP A05: Security Misconfiguration)
# ----------------------------------------------------------------------

@app.after_request
def set_security_headers(response: Response) -> Response:
    """
    Aplica cabeçalhos defensivos recomendados em todas as respostas HTTP.
    """
    # Previne que a página seja carregada dentro de <frame>, <iframe> ou <embed> (Anti-Clickjacking)
    response.headers["X-Frame-Options"] = "DENY"
    
    # Previne detecção incorreta de tipo MIME pelo navegador (Anti-MIME Sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Restringe compartilhamento de informações do Referer
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Restringe o acesso a recursos do dispositivo (câmera, microfone, geolocalização)
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    
    # Content Security Policy (CSP): Mitiga XSS restringindo a origem de scripts e recursos
    csp_directives = [
        "default-src 'self'",
        "img-src 'self' data: https:",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "script-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    
    return response

# ----------------------------------------------------------------------
# Controle de Acesso Baseado em Sessão (OWASP A01: Broken Access Control)
# ----------------------------------------------------------------------

def login_required(f):
    """
    Decorador que garante que o usuário esteja autenticado no servidor.
    Se não autenticado, redireciona para o login com mensagem informativa.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "username" not in session:
            flash("Acesso restrito. Por favor, autentique-se para continuar.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def get_db_path() -> str:
    """Retorna o caminho do banco configurado na aplicação."""
    return app.config.get("DATABASE_PATH", Config.DATABASE_PATH)

# ----------------------------------------------------------------------
# Rotas Públicas
# ----------------------------------------------------------------------

@app.route("/")
def home():
    """
    Tela inicial pública: Vitrine dos pontos turísticos de Maceió ativos/selecionados.
    Inclui filtro por categoria e botão para a Área Administrativa.
    """
    category_filter = request.args.get("category", "").strip()
    all_active = get_active_tourist_spots(get_db_path())
    
    # Coleta categorias distintas para exibição dos botões de filtro
    categories = sorted(list({spot["category"] for spot in all_active}))
    
    if category_filter:
        spots = [s for s in all_active if s["category"] == category_filter]
    else:
        spots = all_active
        
    is_authenticated = "user_id" in session
    return render_template(
        "home.html",
        spots=spots,
        categories=categories,
        selected_category=category_filter,
        is_authenticated=is_authenticated,
        total_spots=len(spots),
    )

# ----------------------------------------------------------------------
# Rotas de Autenticação (OWASP A07)
# ----------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Tela de autenticação segura.
    Aplica rate limiting, hashing de senhas e prevenção contra enumeração de usuários.
    """
    if "user_id" in session:
        return redirect(url_for("admin"))
        
    if request.method == "POST":
        client_ip = request.remote_addr or "127.0.0.1"
        
        # 1. Verificação de Força Bruta (Rate Limiting)
        limited, retry_after = is_rate_limited(client_ip)
        if limited:
            flash(
                f"Muitas tentativas de login consecutivas. Por segurança, tente novamente em {retry_after} segundos.",
                "danger"
            )
            return render_template("login.html"), 429
            
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Validação básica de entrada
        if not username or not password or len(username) > 80 or len(password) > 128:
            record_failed_attempt(client_ip)
            flash("Credenciais inválidas. Verifique o usuário e a senha informados.", "danger")
            return render_template("login.html"), 401
            
        user = get_user_by_username(username, get_db_path())
        
        # OWASP A07: Comparação com hash seguro e mensagem genérica contra enumeração
        if user and check_password_hash(user["password_hash"], password):
            # Prevenção contra Session Fixation: Limpa e regenera a sessão
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session.permanent = True
            
            # Gera novo token CSRF para a nova sessão autenticada
            session["_csrf_token"] = secrets.token_hex(32)
            reset_attempts(client_ip)
            
            flash(f"Bem-vindo(a), {user['username']}! Acesso administrativo concedido.", "success")
            
            # Validação da URL de redirecionamento (Open Redirect Prevention)
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("admin"))
        else:
            record_failed_attempt(client_ip)
            # Mensagem uniforme (não revela se o usuário existe ou não)
            flash("Credenciais inválidas. Verifique o usuário e a senha informados.", "danger")
            return render_template("login.html"), 401
            
    return render_template("login.html")

@app.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Encerra a sessão do usuário de forma segura, invalidando cookies e dados em memória.
    """
    session.clear()
    flash("Sessão encerrada com sucesso.", "info")
    return redirect(url_for("home"))

# ----------------------------------------------------------------------
# Área Administrativa Protegida (OWASP A01)
# ----------------------------------------------------------------------

@app.route("/admin")
@login_required
def admin():
    """
    Página interna restrita: Permite ao gestor selecionar quais pontos turísticos
    deverão ser apresentados na página Home do portal.
    """
    spots = get_all_tourist_spots(get_db_path())
    active_count = sum(1 for s in spots if s["is_active"] == 1)
    inactive_count = len(spots) - active_count
    
    return render_template(
        "admin.html",
        spots=spots,
        active_count=active_count,
        inactive_count=inactive_count,
        username=session.get("username", "Administrador"),
    )

@app.route("/admin/toggle-spot/<int:spot_id>", methods=["POST"])
@login_required
def toggle_spot(spot_id: int):
    """
    Ação administrativa: Ativa ou desativa a exibição de um ponto turístico na Home.
    Requer autenticação no servidor e proteção anti-CSRF.
    """
    spot = get_spot_by_id(spot_id, get_db_path())
    if not spot:
        abort(404, description="Ponto turístico não encontrado.")
        
    new_status = toggle_spot_visibility(spot_id, get_db_path())
    if new_status is not None:
        status_label = "ativado e visível na Home" if new_status == 1 else "desativado da Home"
        flash(f"Ponto turístico '{spot['title']}' foi {status_label}.", "success")
    else:
        flash("Ocorreu um erro ao atualizar o status do ponto turístico.", "danger")
        
    return redirect(url_for("admin"))

# ----------------------------------------------------------------------
# Tratamento Seguro de Erros HTTP
# ----------------------------------------------------------------------

@app.errorhandler(401)
def unauthorized(error):
    return render_template("error.html", code=401, title="Não Autorizado", description=str(error)), 401

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, title="Acesso Proibido", description=str(error)), 403

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, title="Página Não Encontrada", description="O recurso solicitado não existe."), 404

@app.errorhandler(429)
def too_many_requests(error):
    return render_template("error.html", code=429, title="Muitas Requisições", description=str(error)), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template("error.html", code=500, title="Erro Interno", description="Ocorreu um erro inesperado no servidor."), 500

# ----------------------------------------------------------------------
# Inicialização Automática do Banco de Dados
# ----------------------------------------------------------------------
with app.app_context():
    seed_database()

if __name__ == "__main__":
    # Em desenvolvimento local; em produção na Oracle Cloud usar Gunicorn
    app.run(host="127.0.0.1", port=5000, debug=False)
