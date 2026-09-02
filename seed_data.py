"""
Módulo de Povoamento Inicial (Seeding) do Banco de Dados.
Cadastra pontos turísticos reais e reconhecidos de Maceió com fontes confiáveis
e cria o usuário administrador inicial com senha protegida por hash criptográfico
(OWASP A07:2025 - Identification and Authentication Failures).
"""

from typing import Optional
from werkzeug.security import generate_password_hash
from config import Config
from database import (
    init_db,
    get_user_by_username,
    create_user,
    get_all_tourist_spots,
    insert_tourist_spot,
)

# Acervo curado de pontos turísticos de Maceió/AL com dados de órgãos oficiais e fontes confiáveis
TOURIST_SPOTS_DATA = [
    {
        "title": "Piscinas Naturais e Praia de Pajuçara",
        "description": (
            "Cartão-postal histórico de Maceió. Na maré baixa, tradicionais jangadas a vela "
            "conduzem visitantes por 2 km mar adentro até aquários naturais de águas calmas, "
            "cristalinas e repletas de peixes coloridos protegidos por recifes de corais."
        ),
        "category": "Praia & Ecoturismo",
        "location": "Bairro Pajuçara, Maceió - AL",
        "image_url": "/static/images/pajucara.svg",
        "source_credit": "Secretaria Municipal de Turismo de Maceió (SEMTUR)",
        "is_active": 1,
        "display_order": 1,
    },
    {
        "title": "Farol e Orla da Ponta Verde",
        "description": (
            "Com sua arquitetura cilíndrica pintada em listras vermelhas e brancas, o Farol da Ponta Verde "
            "ergue-se sobre os arrecifes. Durante as marés baixas (0.0 a 0.3), é possível caminhar sobre os corais "
            "até a base do farol, desfrutando de quiosques gastronômicos renomados."
        ),
        "category": "Patrimônio & Praia",
        "location": "Bairro Ponta Verde, Maceió - AL",
        "image_url": "/static/images/ponta_verde.svg",
        "source_credit": "SEDETUR Alagoas / Guia Oficial de Turismo",
        "is_active": 1,
        "display_order": 2,
    },
    {
        "title": "Praia de Ipioca (Litoral Norte)",
        "description": (
            "Localizada a cerca de 20 km do centro, Ipioca encanta pela preservação ecológica: "
            "mar calmo com tonalidade azul-turquesa inconfundível, areias claras e extensos coqueirais. "
            "Ideal para quem busca sossego e contato direto com a natureza litorânea alagoana."
        ),
        "category": "Praia & Natureza",
        "location": "Ipioca, Maceió - AL",
        "image_url": "/static/images/ipioca.svg",
        "source_credit": "Portal Oficial Visite Alagoas / Governo de Alagoas",
        "is_active": 1,
        "display_order": 3,
    },
    {
        "title": "Pavilhão do Artesanato",
        "description": (
            "Espaço cultural vibrante na orla de Pajuçara que reúne centenas de mestres artesãos. "
            "Destaque para o autêntico 'Bordado Filé', reconhecido como Patrimônio Cultural Imaterial de Alagoas, "
            "além de rendas renascença, cerâmicas do Pontal e iguarias locais como castanhas e doces."
        ),
        "category": "Cultura & Artesanato",
        "location": "Avenida Doutor Antônio Gouveia, Pajuçara",
        "image_url": "/static/images/artesanato.svg",
        "source_credit": "IPHAN / Secretaria de Estado da Cultura (SECULT/AL)",
        "is_active": 1,
        "display_order": 4,
    },
    {
        "title": "Mirante de São Gonçalo",
        "description": (
            "Localizado no histórico bairro do Farol, proporciona uma vista panorâmica de tirar o fôlego "
            "da enseada de Jaraguá, do Porto de Maceió e da transição entre o centro colonial e as águas esmeraldas "
            "do Oceano Atlântico. Ponto imperdível para contemplar o pôr do sol."
        ),
        "category": "Mirante & Vista Panorâmica",
        "location": "Bairro do Farol (Próximo à Igreja de São Gonçalo)",
        "image_url": "/static/images/sao_goncalo.svg",
        "source_credit": "Fundação Municipal de Ação Cultural de Maceió (FMAC)",
        "is_active": 1,
        "display_order": 5,
    },
    {
        "title": "Memorial Teotônio Vilela",
        "description": (
            "Monumento e centro cultural de traços sinuosos concebido pelo mestre Oscar Niemeyer na orla marítima. "
            "Homenageia a trajetória do senador alagoano Teotônio Vilela, o 'Menestrel das Alagoas', símbolo da anistia "
            "e redemocratização política do Brasil."
        ),
        "category": "História & Arquitetura",
        "location": "Orla de Pajuçara, Maceió - AL",
        "image_url": "/static/images/teotonio_vilela.svg",
        "source_credit": "Fundação Oscar Niemeyer / Prefeitura de Maceió",
        "is_active": 1,
        "display_order": 6,
    },
    {
        "title": "Praia do Francês (Litoral Sul Metropolitano)",
        "description": (
            "Localizada em Marechal Deodoro, na região metropolitana de Maceió, é uma das praias mais famosas de Alagoas. "
            "Possui duas facetas: o lado esquerdo, protegido por uma vasta barreira de corais com mar calmo tipo piscina, "
            "e o lado direito, com mar aberto propício para a prática de surf."
        ),
        "category": "Praia & Esportes",
        "location": "Marechal Deodoro (a 20 minutos de Maceió)",
        "image_url": "/static/images/frances.svg",
        "source_credit": "Secretaria de Estado do Desenvolvimento Econômico e Turismo (SEDETUR)",
        "is_active": 1,
        "display_order": 7,
    },
    {
        "title": "Praia e Bairro de Garça Torta",
        "description": (
            "Refúgio boêmio e bucólico no litoral norte da capital. Com ambiente de vila de pescadores, "
            "abriga ateliês de artistas plásticos, quiosques charmosos à beira-mar e gastronomia marcante à base "
            "de frutos do mar frescos e caldinho de sururu."
        ),
        "category": "Gastronomia & Vila de Pescadores",
        "location": "Litoral Norte, Maceió - AL",
        "image_url": "/static/images/garca_torta.svg",
        "source_credit": "SEMTUR Maceió / Associação dos Moradores de Garça Torta",
        "is_active": 1,
        "display_order": 8,
    },
]

def seed_database(db_path: Optional[str] = None) -> None:
    """
    Inicializa o banco de dados e insere registros de teste caso estejam vazios.
    """
    init_db(db_path)
    
    # 1. Criação do Usuário Administrador com Senha Hashed (OWASP A07)
    admin_user = Config.DEFAULT_ADMIN_USER
    existing_user = get_user_by_username(admin_user, db_path)
    if not existing_user:
        # Hashing forte com sal automático (PBKDF2/scrypt via werkzeug)
        hashed_password = generate_password_hash(
            Config.DEFAULT_ADMIN_PASS,
            method="scrypt"
        )
        create_user(
            username=admin_user,
            password_hash=hashed_password,
            role="admin",
            db_path=db_path
        )
        print(f"[SEED] Usuário administrador '{admin_user}' criado com hash seguro.")
    else:
        print(f"[SEED] Usuário administrador '{admin_user}' já existe.")
        
    # 2. Inserção dos Pontos Turísticos se a tabela estiver vazia
    existing_spots = get_all_tourist_spots(db_path)
    if len(existing_spots) == 0:
        for spot in TOURIST_SPOTS_DATA:
            insert_tourist_spot(
                title=spot["title"],
                description=spot["description"],
                category=spot["category"],
                location=spot["location"],
                image_url=spot["image_url"],
                source_credit=spot["source_credit"],
                is_active=spot["is_active"],
                display_order=spot["display_order"],
                db_path=db_path
            )
        print(f"[SEED] {len(TOURIST_SPOTS_DATA)} pontos turísticos cadastrados com sucesso.")
    else:
        print(f"[SEED] Pontos turísticos já cadastrados ({len(existing_spots)} registros existentes).")

if __name__ == "__main__":
    seed_database()
