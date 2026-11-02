#!/usr/bin/env bash
# ==============================================================================
# Script de Implantação Contínua (CD) - Portal Maceió Turismo
# Executado automaticamente pelo GitHub Actions ou manualmente na VM
# ==============================================================================

set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/Projeto_Aplicado}"
VENV_DIR="${VENV_DIR:-${APP_DIR}/.venv}"
SERVICE_NAME="${SERVICE_NAME:-maceio-turismo}"

echo "============================================================"
echo "🚀 Iniciando processo de deploy contínuo em: ${APP_DIR}"
echo "📅 Data: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
echo "============================================================"

# 1. Navegar até o diretório da aplicação
if [ ! -d "${APP_DIR}" ]; then
    echo "❌ Erro: Diretório da aplicação ${APP_DIR} não encontrado."
    exit 1
fi
cd "${APP_DIR}"

# 2. Atualizar código a partir da branch principal
echo "📥 1/5 Atualizando repositório a partir da branch 'main'..."
git fetch origin main
git reset --hard origin/main

# 3. Garantir existência e ativação do ambiente virtual
echo "🐍 2/5 Verificando ambiente virtual Python..."
if [ ! -d "${VENV_DIR}" ]; then
    echo "⚠️ Ambiente virtual não encontrado em ${VENV_DIR}. Criando novo venv..."
    python3 -m venv "${VENV_DIR}"
fi

# Ativação do venv
# shellcheck disable=SC1090,SC1091
source "${VENV_DIR}/bin/activate"

# 4. Atualizar dependências e Gunicorn
echo "📦 3/5 Instalando e atualizando dependências..."
pip install --upgrade pip
pip install -r requirements.txt gunicorn

# 5. Executar inicialização do banco de dados e seed seguro se necessário
echo "🗄️ 4/5 Validando banco de dados e dados cadastrais..."
python seed_data.py
if [ -f "maceio_turismo.db" ]; then
    chmod 664 maceio_turismo.db || true
fi

# 6. Atualizar arquivo de serviço systemd se disponível e reiniciar aplicação
echo "🔄 5/5 Reiniciando serviço da aplicação..."
if [ -f "deploy/maceio-turismo.service" ] && [ -d "/etc/systemd/system" ]; then
    if sudo cp deploy/maceio-turismo.service /etc/systemd/system/maceio-turismo.service 2>/dev/null; then
        sudo systemctl daemon-reload 2>/dev/null || true
    fi
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "Reiniciando serviço systemd: ${SERVICE_NAME}..."
    sudo systemctl restart "${SERVICE_NAME}"
    sudo systemctl status "${SERVICE_NAME}" --no-pager
elif pgrep -f "gunicorn.*app:app" >/dev/null 2>&1; then
    echo "Recarregando instâncias em execução do Gunicorn..."
    pkill -HUP -f "gunicorn.*app:app" || true
else
    echo "ℹ️ Serviço systemd ou processo Gunicorn não detectado ativo no momento."
    echo "Inicie manualmente com: sudo systemctl start ${SERVICE_NAME} ou gunicorn -w 2 -b 0.0.0.0:80 app:app"
fi

echo "============================================================"
echo "✅ Deploy concluído com sucesso!"
echo "============================================================"
