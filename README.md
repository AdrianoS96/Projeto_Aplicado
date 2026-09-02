# 🌊 Portal Maceió Turismo — Secure by Design

> **Projeto Aplicado: Práticas de Mercado**  
> Aplicação Web para Divulgação e Gestão dos Pontos Turísticos de Maceió/AL, desenvolvida sob os preceitos de **Secure by Design** e mitigação ativa do **OWASP Top 10:2025**.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework Flask](https://img.shields.io/badge/framework-Flask_3.1-teal.svg)](https://flask.palletsprojects.com/)
[![Security OWASP 2025](https://img.shields.io/badge/security-OWASP_Top_10:2025-green.svg)](https://owasp.org/Top10/2025/)
[![Database SQLite](https://img.shields.io/badge/database-SQLite_Ready-lightgrey.svg)](https://www.sqlite.org/)
[![Tests Pytest](https://img.shields.io/badge/tests-15_passed-success.svg)](https://pytest.org/)

---

## 🌴 1. Visão Geral e Tema Central

O tema central do sistema é a valorização e gestão dos **pontos turísticos de Maceió/AL** ("O Paraíso das Águas"). O portal apresenta atrações consagradas com dados e ilustrações baseadas em fontes confiáveis e oficiais:
- **Secretaria Municipal de Turismo de Maceió (SEMTUR)**;
- **Secretaria de Estado do Desenvolvimento Econômico e Turismo de Alagoas (SEDETUR)**;
- **Instituto do Patrimônio Histórico e Artístico Nacional (IPHAN)**;
- **Portal Oficial Visite Alagoas**.

### Estrutura Funcional:
1. **Página Inicial (Home)**: Vitrine pública com os pontos turísticos selecionados, filtros por categoria (Praias, Ecoturismo, Patrimônio, Cultura, Gastronomia), dados oficiais de localização e fonte, e botão de acesso à área administrativa.
2. **Tela de Autenticação (Login)**: Formulário de acesso seguro com proteção anti-força bruta, token CSRF e mensagens uniformes contra enumeração de usuários.
3. **Área Administrativa Restrita (Painel)**: Acessível exclusivamente após autenticação. Permite ao gestor **selecionar e alternar quais pontos turísticos serão exibidos na Home**, além de monitorar métricas de visibilidade.
4. **Logout Funcional**: Botão para encerramento imediato de sessão, com invalidação completa dos cookies e dados em memória.

---

## 🛡️ 2. Comprovação de Segurança (OWASP Top 10:2025)

Em conformidade com os critérios obrigatórios de aprovação, o código-fonte mitiga ativamente **3 categorias centrais da [OWASP Top 10:2025](https://owasp.org/Top10/2025/)** (mais proteções adicionais):

### 1. A01:2025 – Broken Access Control (Quebra de Controle de Acesso)
* **Problema mitigado**: Usuários não autenticados tentando acessar endpoints administrativos ou manipular pontos turísticos sem autorização.
* **Onde no código**:
  - `app.py`: Decorador `@login_required` (linhas ~154-160).
  - `app.py`: Rotas protegidas `/admin` e `/admin/toggle-spot/<int:spot_id>`.
* **Como previne**:
  - A verificação de sessão (`session.get("user_id")`) ocorre **estritamente no servidor (Backend)** antes de qualquer execução de lógica ou renderização.
  - Tentativas de acesso não autenticado a rotas protegidas sofrem redirecionamento imediato (HTTP 302) para a tela de `/login` com alerta de acesso negado.
  - IDs de recursos recebidos são fortemente tipados (`<int:spot_id>`) e verificados no banco de dados, prevenindo referências diretas inseguras a objetos (IDOR).
  - Após o login, a sessão é regenerada com `session.clear()`, mitigando ataques de *Session Fixation*.

### 2. A03:2025 – Injection / Cross-Site Scripting (Injeção e XSS)
* **Problema mitigado**: Manipulação de consultas SQL (SQL Injection) via parâmetros de entrada e injeção de scripts maliciosos (XSS) nos navegadores dos visitantes.
* **Onde no código**:
  - `database.py`: Funções `get_active_tourist_spots()`, `get_all_tourist_spots()`, `get_spot_by_id()`, `toggle_spot_visibility()`, `get_user_by_username()` e `create_user()`.
  - `app.py`: Middleware de cabeçalhos de segurança `set_security_headers()` (linhas ~120-150).
  - `templates/*.html`: Renderização contextual com Jinja2.
* **Como previne**:
  - **SQL Injection**: Uso rigoroso e exclusivo de **Consultas Parametrizadas (*Prepared Statements*)** com placeholders `?` via driver padrão `sqlite3`. Nenhuma entrada de usuário é concatenada ou interpolada diretamente em comandos SQL.
  - **Stored & Reflected XSS**: O motor de templates **Jinja2** aplica escape automático (*auto-escaping*) em todas as variáveis exibidas no HTML.
  - **Content Security Policy (CSP)**: Injeção do cabeçalho HTTP `Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data: https:; ...`, impedindo a execução de scripts embutidos não autorizados ou carregamento de domínios maliciosos.

### 3. A07:2025 – Identification and Authentication Failures (Falhas de Identificação e Autenticação)
* **Problema mitigado**: Ataques de força bruta contra senhas, armazenamento inseguro de credenciais, sequestro de sessões e enumeração de usuários.
* **Onde no código**:
  - `app.py`: Funções `is_rate_limited()`, `record_failed_attempt()`, `reset_attempts()` e rota `/login`.
  - `seed_data.py`: Geração de hash com `generate_password_hash(..., method='scrypt')`.
  - `config.py`: Definições `SESSION_COOKIE_HTTPONLY = True` e `SESSION_COOKIE_SAMESITE = 'Lax'`.
  - `app.py`: Rota `/logout` com `session.clear()`.
* **Como previne**:
  - **Hashing Criptográfico Robusto**: Senhas nunca são salvas em texto puro. Utiliza-se o algoritmo **scrypt** com sal dinâmico por padrão da biblioteca `werkzeug.security`.
  - **Defesa Anti-Força Bruta (Rate Limiting)**: Controle em memória por IP que bloqueia tentativas excessivas de login após 5 falhas consecutivas em uma janela de 5 minutos, respondendo com **HTTP 429 (Too Many Requests)**.
  - **Anti-Enumeração de Usuários**: Mensagem de erro idêntica ("*Credenciais inválidas. Verifique o usuário e a senha informados.*") tanto para usuários não encontrados quanto para senhas incorretas, sempre com **HTTP 401**.
  - **Cookies de Sessão Seguros**: O atributo `HttpOnly` impede que códigos JavaScript leiam os cookies de sessão (`document.cookie`), e `SameSite=Lax` previne vazamento em navegações externas.
  - **Destruição Total no Logout**: O encerramento de sessão limpa todos os dados de estado no servidor.

### 4. Proteções Adicionais Implementadas (Bônus de Segurança)
* **Proteção Anti-CSRF (Cross-Site Request Forgery)**: Implementação do padrão *Synchronizer Token Pattern* (`secrets.token_hex(32)`) validado obrigatoriamente no middleware `@app.before_request` para todas as requisições que alteram estado (`POST`). Requisições sem token ou com token divergente são rejeitadas com **HTTP 403 Forbidden**.
* **Cabeçalhos Defensivos HTTP (OWASP A05: Security Misconfiguration)**:
  - `X-Frame-Options: DENY` (previne ataques de Clickjacking);
  - `X-Content-Type-Options: nosniff` (impede MIME sniffing malicioso);
  - `Referrer-Policy: strict-origin-when-cross-origin`;
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`.

---

## 🏗️ 3. Estrutura do Projeto

```
Projeto_Aplicado/
├── app.py                      # Aplicação Flask (rotas, middleware de segurança, CSRF e auth)
├── config.py                   # Parâmetros de segurança e configuração de ambiente
├── database.py                 # Camada de banco de dados SQLite com queries parametrizadas
├── seed_data.py                # Script de seeding com dados confiáveis dos pontos de Maceió
├── requirements.txt            # Dependências mínimas e versionadas do Python
├── .gitignore                  # Arquivo para ignorar arquivos temporários, venv e caches
├── static/
│   ├── css/
│   │   └── style.css           # Design moderno, responsivo com paleta de cores de Maceió
│   ├── js/
│   │   └── main.js             # Scripts do cliente (fechamento de alertas e acessibilidade)
│   └── images/                 # Ilustrações e imagens vetoriais dos pontos turísticos de Maceió
│       ├── pajucara.svg
│       ├── ponta_verde.svg
│       ├── ipioca.svg
│       ├── artesanato.svg
│       ├── sao_goncalo.svg
│       ├── teotonio_vilela.svg
│       ├── frances.svg
│       └── garca_torta.svg
├── templates/
│   ├── base.html               # Layout base acessível com navbar, flash messages e footer
│   ├── home.html               # Vitrine pública dos pontos turísticos ativos de Maceió
│   ├── login.html              # Tela de autenticação com CSRF e notas de segurança
│   ├── admin.html              # Painel administrativo de curadoria e logout funcional
│   └── error.html              # Tela de erro genérica e segura (sem vazamento de stack trace)
└── tests/
    └── test_app.py             # Suíte com 15 testes automatizados (segurança, auth e regras)
```

---

## 🚀 4. Como Executar o Projeto Localmente

### Pré-requisitos
- Python 3.10 ou superior instalado na máquina.

### Passo a Passo

1. **Clonar o Repositório e Acessar a Branch de Desenvolvimento**:
   ```bash
   git clone https://github.com/AdrianoS96/Projeto_Aplicado.git
   cd Projeto_Aplicado
   git checkout feat/maceio-turismo-auth
   ```

2. **Criar e Ativar o Ambiente Virtual (venv)**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Instalar as Dependências**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Inicializar o Banco de Dados e os Pontos Turísticos**:
   ```bash
   python seed_data.py
   ```

5. **Executar a Suíte de Testes Automatizados (Garantia de Qualidade)**:
   ```bash
   python -m pytest tests/test_app.py -v
   ```
   *Todos os 15 testes de segurança e negócio devem passar com 100% de sucesso.*

6. **Iniciar o Servidor de Desenvolvimento**:
   ```bash
   python app.py
   ```
   Acesse no seu navegador: **`http://127.0.0.1:5000/`**

---

## 🔑 5. Credenciais Padrão de Avaliação

Para testar a área administrativa e a funcionalidade de curadoria dos pontos turísticos:

| Campo | Valor Padrão |
| :--- | :--- |
| **URL de Login** | `http://127.0.0.1:5000/login` |
| **Usuário** | `admin` |
| **Senha** | `Maceio@Admin2025!` |

> *Nota: A senha é convertida em hash seguro (`scrypt`) antes de qualquer armazenamento no banco de dados.*

---

## ☁️ 6. Guia de Implantação no Oracle Cloud Free Tier (VM Always Free)

A arquitetura foi projetada especificamente para ser **extremamente leve**, rodando sem custos em instâncias gratuitas da Oracle Cloud Infrastructure (OCI Compute Ampere A1 ou AMD micro com 1 GB de RAM).

### Vantagens do SQLite e Flask no Free Tier:
- **Zero consumo residual de memória RAM**: Não necessita de daemons pesados de bancos de dados (como PostgreSQL ou MySQL, que consomem 300MB a 600MB de RAM ociosos). O SQLite funciona em arquivo direto com zero overhead.
- **Pegada de memória mínima**: A aplicação Flask consome menos de 45 MB de RAM.

### Passo a Passo na VM Oracle Cloud (Ubuntu):

1. **Instalar pacotes básicos e clonar**:
   ```bash
   sudo apt update && sudo apt install -y python3 python3-venv git
   git clone https://github.com/AdrianoS96/Projeto_Aplicado.git
   cd Projeto_Aplicado
   git checkout feat/maceio-turismo-auth
   ```

2. **Criar venv e instalar**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt gunicorn
   python seed_data.py
   ```

3. **Executar com Gunicorn como serviço em segundo plano**:
   ```bash
   gunicorn -w 2 -b 0.0.0.0:80 app:app
   ```

4. **Liberar a porta no firewall da VM (iptables / ufw)**:
   ```bash
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo netfilter-persistent save
   ```
   *(Lembre-se também de adicionar a Ingress Rule para a porta 80/TCP na Security List da sua VCN na console da Oracle Cloud).*

---

## 🤖 7. Codificação Assistida por IA (Google Antigravity)

O desenvolvimento deste protótipo seguro foi realizado com o auxílio do **Google Antigravity IDE**:
- **Design de Segurança**: Definição de arquitetura defensiva *Secure by Design* para mitigar vulnerabilidades da OWASP Top 10:2025.
- **Auditoria de Código**: Análise estática contra injeção de comandos, validação contextual de tokens CSRF e cabeçalhos defensivos.
- **Geração de Testes**: Elaboração de testes de regressão automatizados para validação de integridade de sessão, rate limiting e controle de acesso.

---

## 🌿 8. Estratégia de Branches Git e Commits

O projeto adota o fluxo de trabalho moderno baseado em branches de funcionalidade e a convenção de **Conventional Commits**:
- **Branch principal**: `main` (preservada para versões estáveis).
- **Branch de entrega**: `feat/maceio-turismo-auth` (onde todas as implementações foram desenvolvidas e commitadas).
- **Padrão de commits**:
  - `feat: ...` para novas funcionalidades;
  - `test: ...` para suíte de testes automatizados;
  - `docs: ...` para documentações e guias;
  - `chore: ...` para configurações e dependências.
