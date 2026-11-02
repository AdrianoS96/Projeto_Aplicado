"""
Suíte de Testes Automatizados - Portal Turístico de Maceió
Validação formal de funcionalidades e requisitos de segurança (OWASP Top 10:2025).
"""

import os
import pytest
import tempfile
from flask import session
from app import app, _login_attempts
from config import Config
from database import init_db, get_db_connection, get_all_tourist_spots, get_user_by_username
from seed_data import seed_database

@pytest.fixture
def client():
    """Configura o cliente de testes com um banco de dados SQLite isolado e temporário."""
    # Garante credencial de teste dinâmica na suíte de testes
    if not Config.DEFAULT_ADMIN_PASS:
        Config.DEFAULT_ADMIN_PASS = "TestSecurePassword#2025"

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app.config["DATABASE_PATH"] = db_path
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    
    # Limpa tentativas de rate limiting acumuladas
    _login_attempts.clear()

    with app.app_context():
        init_db(db_path)
        seed_database(db_path)

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    if os.path.exists(db_path):
        os.remove(db_path)

def get_csrf_token(client):
    """Auxiliar para obter o token CSRF de uma sessão limpa."""
    response = client.get("/login")
    assert response.status_code == 200
    with client.session_transaction() as sess:
        return sess.get("_csrf_token")

# ======================================================================
# 1. Testes de Vitrine Pública (Home)
# ======================================================================

def test_home_page_loads_successfully(client):
    """Verifica se a página inicial carrega com código 200 e elementos de Maceió."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Maceió Turismo" in html
    assert "Piscinas Naturais" in html
    assert "Farol da Ponta Verde" in html
    assert "Área Restrita / Login" in html

def test_home_page_category_filter(client):
    """Verifica se a filtragem por categoria na Home funciona corretamente."""
    response = client.get("/", query_string={"category": "Praia & Ecoturismo"})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Piscinas Naturais e Praia de Pajuçara" in html

# ======================================================================
# 2. Testes de Controle de Acesso (OWASP A01: Broken Access Control)
# ======================================================================

def test_admin_page_unauthenticated_redirects_to_login(client):
    """
    OWASP A01: Usuário anônimo que tenta acessar o /admin diretamente
    deve ser bloqueado e redirecionado para /login.
    """
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

def test_admin_toggle_spot_unauthenticated_blocked(client):
    """
    OWASP A01: Requisição de alteração de estado sem autenticação
    é bloqueada (redirecionamento ou recusa).
    """
    csrf_token = get_csrf_token(client)
    response = client.post("/admin/toggle-spot/1", data={"csrf_token": csrf_token}, follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

def test_admin_page_accessible_when_authenticated(client):
    """Usuário com sessão válida acessa o painel administrativo normalmente."""
    csrf_token = get_csrf_token(client)
    # Efetua login
    login_res = client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": Config.DEFAULT_ADMIN_USER,
            "password": Config.DEFAULT_ADMIN_PASS,
        },
        follow_redirects=True,
    )
    assert login_res.status_code == 200
    assert "Painel de Gestão da Vitrine Turística" in login_res.get_data(as_text=True)
    assert "Encerrar Sessão (Logout)" in login_res.get_data(as_text=True)

# ======================================================================
# 3. Testes de Autenticação e Hashing Seguro (OWASP A07 & A03)
# ======================================================================

def test_login_invalid_password_returns_401(client):
    """
    OWASP A07: Senha incorreta resulta em 401 e mensagem genérica (anti-enumeração).
    """
    csrf_token = get_csrf_token(client)
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": "admin",
            "password": "SenhaCompletamenteIncorreta123!",
        },
    )
    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Credenciais inválidas" in html

def test_login_nonexistent_user_returns_401(client):
    """
    OWASP A07: Usuário inexistente retorna a mesma mensagem de credenciais inválidas.
    """
    csrf_token = get_csrf_token(client)
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": "usuario_fantasma_xyz",
            "password": "qualquer_senha",
        },
    )
    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Credenciais inválidas" in html

def test_password_is_hashed_in_database(client):
    """
    OWASP A07 / A02: A senha nunca deve ser persistida em texto puro no banco.
    """
    user = get_user_by_username(Config.DEFAULT_ADMIN_USER, app.config["DATABASE_PATH"])
    assert user is not None
    assert user["password_hash"] != Config.DEFAULT_ADMIN_PASS
    assert user["password_hash"].startswith("scrypt:")

def test_sql_injection_attempt_in_login(client):
    """
    OWASP A03: Tentativa de SQL Injection (' OR '1'='1) não deve autenticar o usuário.
    """
    csrf_token = get_csrf_token(client)
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": "' OR 1=1 --",
            "password": "' OR 1=1 --",
        },
    )
    assert response.status_code == 401
    with client.session_transaction() as sess:
        assert "user_id" not in sess

def test_rate_limiting_blocks_brute_force(client):
    """
    OWASP A07: Excesso de tentativas de login falhas ativa o Rate Limiting (HTTP 429).
    """
    csrf_token = get_csrf_token(client)
    # Executa MAX_LOGIN_ATTEMPTS tentativas falhas
    for _ in range(Config.MAX_LOGIN_ATTEMPTS):
        client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "username": "admin",
                "password": "senha_errada",
            },
        )

    # A tentativa subsequente deve ser bloqueada por rate limit
    blocked_response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": "admin",
            "password": "senha_errada",
        },
    )
    assert blocked_response.status_code == 429
    assert "Muitas tentativas de login consecutivas" in blocked_response.get_data(as_text=True)

def test_logout_clears_session(client):
    """
    Verifica se o logout limpa completamente a sessão do usuário.
    """
    csrf_token = get_csrf_token(client)
    # Login
    client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": Config.DEFAULT_ADMIN_USER,
            "password": Config.DEFAULT_ADMIN_PASS,
        },
    )
    # Após login bem-sucedido, obtém o novo token gerado pós-regeneração de sessão (OWASP A07)
    with client.session_transaction() as sess:
        auth_csrf_token = sess["_csrf_token"]
    # Logout
    logout_res = client.post("/logout", data={"csrf_token": auth_csrf_token}, follow_redirects=True)
    assert logout_res.status_code == 200
    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert "username" not in sess

# ======================================================================
# 4. Testes de Proteção Anti-CSRF
# ======================================================================

def test_post_without_csrf_token_is_forbidden(client):
    """
    CSRF: Requisição POST sem token de proteção deve retornar HTTP 403 Forbidden.
    """
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "alguma_senha",
        },
    )
    assert response.status_code == 403
    assert "Falha na validação do token CSRF" in response.get_data(as_text=True)

def test_post_with_invalid_csrf_token_is_forbidden(client):
    """
    CSRF: Requisição POST com token adulterado deve ser rejeitada com 403 Forbidden.
    """
    client.get("/login")  # Inicia sessão
    response = client.post(
        "/login",
        data={
            "csrf_token": "token_falsificado_invalido_123456",
            "username": "admin",
            "password": "alguma_senha",
        },
    )
    assert response.status_code == 403

# ======================================================================
# 5. Testes de Curadoria e Gestão da Vitrine (Admin & Home)
# ======================================================================

def test_toggle_tourist_spot_visibility(client):
    """
    Verifica a funcionalidade central de curadoria:
    O administrador altera o status de um ponto turístico de ativo para inativo.
    O ponto deixa de ser exibido na página inicial (Home).
    """
    csrf_token = get_csrf_token(client)
    
    # 1. Login do Administrador
    client.post(
        "/login",
        data={
            "csrf_token": csrf_token,
            "username": Config.DEFAULT_ADMIN_USER,
            "password": Config.DEFAULT_ADMIN_PASS,
        },
    )

    # 2. Localiza o primeiro ponto turístico e obtém o token CSRF pós-login
    with client.session_transaction() as sess:
        auth_csrf_token = sess["_csrf_token"]

    spots = get_all_tourist_spots(app.config["DATABASE_PATH"])
    first_spot = spots[0]
    spot_id = first_spot["id"]
    spot_title = first_spot["title"]

    # Verifica que inicialmente está visível na Home
    home_before = client.get("/")
    assert spot_title in home_before.get_data(as_text=True)

    # 3. Administrador desativa a visibilidade do ponto
    toggle_res = client.post(f"/admin/toggle-spot/{spot_id}", data={"csrf_token": auth_csrf_token}, follow_redirects=True)
    assert toggle_res.status_code == 200
    assert "desativado da Home" in toggle_res.get_data(as_text=True)

    # 4. Verifica que o ponto agora NÃO está mais presente na Home
    home_after = client.get("/")
    assert spot_title not in home_after.get_data(as_text=True)

    # 5. Administrador reativa o ponto
    reactivate_res = client.post(f"/admin/toggle-spot/{spot_id}", data={"csrf_token": auth_csrf_token}, follow_redirects=True)
    assert reactivate_res.status_code == 200
    assert "ativado e visível na Home" in reactivate_res.get_data(as_text=True)

    # 6. Verifica que o ponto voltou a ser exibido na Home
    home_final = client.get("/")
    assert spot_title in home_final.get_data(as_text=True)

# ======================================================================
# 6. Testes de Cabeçalhos de Segurança HTTP (OWASP A05)
# ======================================================================

def test_security_headers_present_in_responses(client):
    """
    OWASP A05: Verifica se as respostas HTTP contêm os cabeçalhos de proteção.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert response.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert response.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert "Content-Security-Policy" in response.headers
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy")

# ======================================================================
# 7. Testes das Mitigações Adicionais de Segurança (Hardening Audit)
# ======================================================================

def test_open_redirect_attempts_blocked(client):
    """
    OWASP A01 / CWE-601: Tentativas de redirecionamento aberto no parâmetro 'next'
    devem ser neutralizadas, direcionando sempre para /admin por segurança.
    """
    csrf_token = get_csrf_token(client)
    malicious_next_urls = [
        "//attacker.com",
        "//attacker.com/phishing",
        "/\\attacker.com",
        "https://attacker.com",
        "javascript:alert(1)",
    ]

    for malicious_url in malicious_next_urls:
        csrf_token = get_csrf_token(client)
        res = client.post(
            f"/login?next={malicious_url}",
            data={
                "csrf_token": csrf_token,
                "username": Config.DEFAULT_ADMIN_USER,
                "password": Config.DEFAULT_ADMIN_PASS,
            },
            follow_redirects=False,
        )
        assert res.status_code == 302
        assert res.headers["Location"] == "/admin", f"Open redirect não foi bloqueado para {malicious_url}"
        with client.session_transaction() as sess:
            sess.clear()


def test_open_redirect_valid_relative_url_allowed(client):
    """
    Garante que caminhos relativos legítimos continuam sendo respeitados no 'next'.
    """
    csrf_token = get_csrf_token(client)
    res = client.post(
        "/login?next=/admin",
        data={
            "csrf_token": csrf_token,
            "username": Config.DEFAULT_ADMIN_USER,
            "password": Config.DEFAULT_ADMIN_PASS,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert res.headers["Location"] == "/admin"


def test_logout_get_rejected_with_405(client):
    """
    OWASP A08 / CWE-352: Requisição GET em /logout deve ser rejeitada com 405 Method Not Allowed,
    impedindo ataques de CSRF de desconexão forçada via tags <img> ou links externos.
    """
    res = client.get("/logout")
    assert res.status_code == 405


def test_max_content_length_is_configured():
    """
    OWASP A05 / CWE-400: Garante que a aplicação possui limite de tamanho de payload definido.
    """
    assert hasattr(Config, "MAX_CONTENT_LENGTH")
    assert Config.MAX_CONTENT_LENGTH > 0
    assert Config.MAX_CONTENT_LENGTH <= 10 * 1024 * 1024  # Máximo razoável de 10 MB

