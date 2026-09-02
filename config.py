"""
Módulo de Configuração da Aplicação Maceió Turismo.
Aplica princípios de Secure by Design (OWASP Top 10:2025).
"""

import os
from datetime import timedelta

class Config:
    """Configurações base com definições rígidas de segurança."""
    
    # Chave secreta criptográfica (OWASP A02: Cryptographic Failures)
    # Em produção, deve ser fornecida via variável de ambiente. Se ausente, gera token seguro em runtime.
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    
    # Caminho do banco de dados SQLite
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "maceio_turismo.db"))
    
    # Segurança de Cookies de Sessão (OWASP A07: Identification and Authentication Failures)
    # Impede que scripts maliciosos (XSS) acessem o cookie de sessão via document.cookie
    SESSION_COOKIE_HTTPONLY = True
    
    # Mitigação contra CSRF através do atributo SameSite
    SESSION_COOKIE_SAMESITE = "Lax"
    
    # Flag Secure: ativa HTTPS para cookies em produção (pode ser desativado para testes HTTP locais)
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    
    # Tempo de expiração de sessão inativa (60 minutos)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    
    # Proteção de Força Bruta (OWASP A07)
    # Máximo de tentativas de login por IP dentro da janela de tempo
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))
    LOGIN_ATTEMPT_WINDOW_SECONDS = int(os.environ.get("LOGIN_ATTEMPT_WINDOW_SECONDS", "300"))  # 5 minutos

    # Credenciais padrão para inicialização administrativa (podem ser alteradas via env)
    DEFAULT_ADMIN_USER = os.environ.get("DEFAULT_ADMIN_USER", "admin")
    DEFAULT_ADMIN_PASS = os.environ.get("DEFAULT_ADMIN_PASS", "DefinaSuaSenhaSegura2025!")
