SISTEMA SKYPORT - SQLITE LOCAL

1) Abra o terminal (PowerShell) na pasta do projeto.
2) Instale as dependências:
   npm install
3) Inicie o servidor:
   npm start
4) Acesse no navegador:
   http://localhost:3000

Banco de dados local: senai.db (criado, migrado e populado automaticamente).

Credenciais de acesso inicial:
- Administrador: admin@senai.local / Admin123!
- COPED (somente leitura): coped@senai.local / Coped123!

Painéis disponíveis:
- http://localhost:3000              -> painel administrativo
- http://localhost:3000/coped.html   -> painel COPED de chaves
- http://localhost:3000/monitor.html -> monitor de acessos e chaves (dados reais)

O monitor usa as APIs do sistema e atualiza os dados a cada 15 segundos.
A aba "Tela do Cliente" funciona sem login e consome a API pública
GET /api/public/salas (somente salas, capacidades e status das chaves,
sem dados pessoais). As demais abas exigem login de Administrador ou COPED.

Testes automatizados:
   npm test

Os testes iniciam um servidor isolado em uma porta de teste (3100), criam um
banco SQLite temporário, executam a bateria completa e removem o banco ao final.
Não é necessário deixar o servidor principal rodando.

Variáveis de ambiente opcionais:
- PORT       -> porta HTTP (padrão: 3000)
- DB_PATH    -> caminho alternativo para o arquivo SQLite
- JWT_SECRET -> chave de assinatura dos tokens JWT (recomendado em produção)

Documentação:
   npm run docs

Gera os relatórios .docx na pasta docs/ e na raiz do projeto.

Não requer Docker nem PostgreSQL.
