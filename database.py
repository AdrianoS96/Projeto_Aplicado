"""
Módulo de Banco de Dados da Aplicação Maceió Turismo.
Aplica mitigação contra SQL Injection (OWASP A03:2025 - Injection)
através de consultas rigorosamente parametrizadas (Prepared Statements).
"""

import sqlite3
import os
from typing import List, Optional, Dict, Any
from config import Config

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Retorna uma conexão configurada com o banco SQLite.
    Habilita suporte a chaves estrangeiras e acesso por nome de coluna (Row).
    """
    path = db_path or Config.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path: Optional[str] = None) -> None:
    """
    Inicializa o esquema relacional do banco de dados caso não exista.
    Cria as tabelas 'users' e 'tourist_spots'.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'admin',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tourist_spots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    location TEXT NOT NULL,
                    image_url TEXT NOT NULL,
                    source_credit TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    display_order INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    finally:
        conn.close()

# ----------------------------------------------------------------------
# Consultas de Pontos Turísticos (Todas estritamente parametrizadas)
# ----------------------------------------------------------------------

def get_active_tourist_spots(db_path: Optional[str] = None) -> List[sqlite3.Row]:
    """
    Recupera apenas os pontos turísticos marcados como ativos para exibição na Home.
    OWASP A03: O parâmetro de filtro é passado de forma parametrizada.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, description, category, location, image_url, source_credit, is_active, display_order
            FROM tourist_spots
            WHERE is_active = ?
            ORDER BY display_order ASC, id ASC
            """,
            (1,)
        )
        return cursor.fetchall()
    finally:
        conn.close()

def get_all_tourist_spots(db_path: Optional[str] = None) -> List[sqlite3.Row]:
    """
    Recupera todos os pontos turísticos para a área administrativa.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, description, category, location, image_url, source_credit, is_active, display_order
            FROM tourist_spots
            ORDER BY display_order ASC, id ASC
            """
        )
        return cursor.fetchall()
    finally:
        conn.close()

def get_spot_by_id(spot_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """
    Busca um ponto turístico específico pelo identificador numérico.
    OWASP A03: O ID numérico é validado e parametrizado.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, description, category, location, image_url, source_credit, is_active
            FROM tourist_spots
            WHERE id = ?
            """,
            (spot_id,)
        )
        return cursor.fetchone()
    finally:
        conn.close()

def toggle_spot_visibility(spot_id: int, db_path: Optional[str] = None) -> Optional[int]:
    """
    Alterna o status de visibilidade de um ponto turístico (ativo <-> inativo).
    Retorna o novo estado (0 ou 1) ou None se não encontrado.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM tourist_spots WHERE id = ?", (spot_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            new_status = 0 if row["is_active"] == 1 else 1
            cursor.execute(
                "UPDATE tourist_spots SET is_active = ? WHERE id = ?",
                (new_status, spot_id)
            )
            return new_status
    finally:
        conn.close()

def insert_tourist_spot(
    title: str,
    description: str,
    category: str,
    location: str,
    image_url: str,
    source_credit: str,
    is_active: int = 1,
    display_order: int = 0,
    db_path: Optional[str] = None
) -> int:
    """
    Insere um novo ponto turístico de forma parametrizada e segura.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tourist_spots (
                    title, description, category, location, image_url, source_credit, is_active, display_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, description, category, location, image_url, source_credit, is_active, display_order)
            )
            return cursor.lastrowid
    finally:
        conn.close()

# ----------------------------------------------------------------------
# Gestão de Usuários e Autenticação (OWASP A03 & A07)
# ----------------------------------------------------------------------

def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """
    Recupera um usuário pelo nome de usuário com consulta parametrizada.
    Previne SQL Injection em tentativas de login maliciosas.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
            (username,)
        )
        return cursor.fetchone()
    finally:
        conn.close()

def create_user(
    username: str,
    password_hash: str,
    role: str = "admin",
    db_path: Optional[str] = None
) -> int:
    """
    Cadastra um novo usuário no banco de dados com hash de senha protegido.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            return cursor.lastrowid
    finally:
        conn.close()
