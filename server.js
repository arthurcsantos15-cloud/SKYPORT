const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "senai-chave-local";
const dbPath = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, "senai.db");
const db = new sqlite3.Database(dbPath);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const run = (s, p = []) =>
  new Promise((ok, no) =>
    db.run(s, p, function (e) {
      e ? no(e) : ok({ id: this.lastID, changes: this.changes });
    })
  );
const all = (s, p = []) =>
  new Promise((ok, no) =>
    db.all(s, p, (e, r) => (e ? no(e) : ok(r)))
  );
const get = (s, p = []) =>
  new Promise((ok, no) =>
    db.get(s, p, (e, r) => (e ? no(e) : ok(r)))
  );

/**
 * Verifica se uma coluna existe em uma tabela.
 * Usado pelas migrações para manter compatibilidade com bancos criados
 * por versões anteriores do sistema.
 */
const hasColumn = async (table, column) => {
  const rows = await all(`PRAGMA table_info(${table})`);
  return rows.some((row) => row.name === column);
};

const addColumnIfMissing = async (table, column, definition) => {
  if (!(await hasColumn(table, column))) {
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
};

const auth = (req, res, next) => {
  try {
    const raw = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!raw) return res.status(401).json({ erro: "Token não fornecido" });
    req.user = jwt.verify(raw, SECRET);
    next();
  } catch (e) {
    res.status(401).json({ erro: "Sessão inválida ou expirada" });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.perfil === "admin") return next();
  res.status(403).json({ erro: "Acesso restrito a administradores" });
};

const adminOrCoped = (req, res, next) => {
  if (req.user && (req.user.perfil === "admin" || req.user.perfil === "coped")) return next();
  res.status(403).json({ erro: "Acesso restrito a administradores ou COPED" });
};

async function init() {
  await run(`CREATE TABLE IF NOT EXISTS areas(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT UNIQUE,
    responsavel TEXT
  )`);
  await run(`CREATE TABLE IF NOT EXISTS funcionarios(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    matricula TEXT UNIQUE,
    area_id INTEGER,
    cargo TEXT,
    dispositivo_id TEXT UNIQUE,
    digital_id TEXT,
    ativo INTEGER DEFAULT 1
  )`);
  await run(`CREATE TABLE IF NOT EXISTS salas(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT UNIQUE,
    capacidade INTEGER,
    status TEXT DEFAULT 'Disponível'
  )`);
  await run(`CREATE TABLE IF NOT EXISTS chaves(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo TEXT UNIQUE,
    sala_id INTEGER,
    status TEXT DEFAULT 'Disponível',
    codigo_alfanumerico TEXT UNIQUE
  )`);
  await run(`CREATE TABLE IF NOT EXISTS retiradas_chaves(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chave_id INTEGER,
    funcionario_id INTEGER,
    retirada TEXT DEFAULT CURRENT_TIMESTAMP,
    devolucao TEXT
  )`);
  await run(`CREATE TABLE IF NOT EXISTS acessos(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    funcionario_id INTEGER,
    data_hora TEXT DEFAULT CURRENT_TIMESTAMP,
    tipo TEXT,
    origem TEXT,
    dispositivo_id TEXT
  )`);
  await run(`CREATE TABLE IF NOT EXISTS usuarios(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    email TEXT UNIQUE,
    senha_hash TEXT,
    perfil TEXT DEFAULT 'admin'
  )`);
  await run(`CREATE TABLE IF NOT EXISTS agendamentos_salas(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sala_id INTEGER NOT NULL,
    funcionario_id INTEGER,
    solicitante_nome TEXT NOT NULL,
    data TEXT NOT NULL,
    hora_inicio TEXT NOT NULL,
    hora_fim TEXT NOT NULL,
    disciplina_motivo TEXT NOT NULL,
    turno TEXT DEFAULT 'Manhã',
    status TEXT DEFAULT 'Confirmado',
    observacoes TEXT,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sala_id) REFERENCES salas(id),
    FOREIGN KEY(funcionario_id) REFERENCES funcionarios(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS veiculos(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    placa TEXT UNIQUE NOT NULL,
    modelo TEXT NOT NULL,
    cor TEXT,
    tipo TEXT DEFAULT 'Carro',
    motorista_nome TEXT NOT NULL,
    categoria TEXT DEFAULT 'Professor',
    funcionario_id INTEGER,
    vaga TEXT,
    status TEXT DEFAULT 'Ocupado',
    entrada_hora TEXT,
    saida_hora TEXT,
    observacoes TEXT,
    criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(funcionario_id) REFERENCES funcionarios(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS veiculos_movimentacoes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    veiculo_id INTEGER NOT NULL,
    placa TEXT NOT NULL,
    tipo_movimentacao TEXT NOT NULL,
    vaga TEXT,
    data_hora TEXT NOT NULL,
    usuario TEXT,
    FOREIGN KEY(veiculo_id) REFERENCES veiculos(id) ON DELETE CASCADE
  )`);

  // Migrações incrementais: cada coluna é verificada de forma independente.
  // A versão anterior aninhava as migrações dentro de um único try/catch, o que
  // impedia a criação de codigo_alfanumerico quando digital_id já existia.
  await addColumnIfMissing("funcionarios", "digital_id", "TEXT");
  await addColumnIfMissing("chaves", "codigo_alfanumerico", "TEXT");
  await addColumnIfMissing("usuarios", "perfil", "TEXT DEFAULT 'admin'");

  await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_func_digital ON funcionarios(digital_id) WHERE digital_id IS NOT NULL");
  await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_chave_alfa ON chaves(codigo_alfanumerico) WHERE codigo_alfanumerico IS NOT NULL");

  for (const n of ["Administração", "Mecânica", "Elétrica", "Informática"]) {
    await run("INSERT OR IGNORE INTO areas(nome) VALUES(?)", [n]);
  }
  for (const x of [
    ["Sala 01", 30, "Disponível"],
    ["Sala 02", 25, "Ocupada"],
    ["Laboratório 01", 20, "Disponível"],
  ]) {
    await run("INSERT OR IGNORE INTO salas(nome,capacidade,status) VALUES(?,?,?)", x);
  }

  const existingAdmin = await get("SELECT id FROM usuarios WHERE email=?", ["admin@senai.local"]);
  if (!existingAdmin) {
    const hash = await bcrypt.hash("Admin123!", 10);
    await run("INSERT INTO usuarios(nome,email,senha_hash,perfil) VALUES(?,?,?,?)", [
      "Administrador",
      "admin@senai.local",
      hash,
      "admin",
    ]);
  }

  // Usuário COPED
  const existingCoped = await get("SELECT id FROM usuarios WHERE email=?", ["coped@senai.local"]);
  if (!existingCoped) {
    const hashCoped = await bcrypt.hash("Coped123!", 10);
    await run("INSERT INTO usuarios(nome,email,senha_hash,perfil) VALUES(?,?,?,?)", [
      "COPED",
      "coped@senai.local",
      hashCoped,
      "coped",
    ]);
  }

  const fCount = await get("SELECT count(*) n FROM funcionarios");
  if (!fCount || fCount.n === 0) {
    await run("INSERT INTO funcionarios(nome,matricula,area_id,cargo,dispositivo_id,digital_id) VALUES(?,?,?,?,?,?)", [
      "Carlos Eduardo Silva",
      "SEN-1001",
      4,
      "Instrutor de TI",
      "TAG-001",
      "DIG-001"
    ]);
    await run("INSERT INTO funcionarios(nome,matricula,area_id,cargo,dispositivo_id,digital_id) VALUES(?,?,?,?,?,?)", [
      "Mariana Souza Santos",
      "SEN-1002",
      1,
      "Coordenadora Pedagógica",
      "TAG-002",
      "DIG-002"
    ]);
    await run("INSERT INTO funcionarios(nome,matricula,area_id,cargo,dispositivo_id,digital_id) VALUES(?,?,?,?,?,?)", [
      "Roberto Oliveira Lima",
      "SEN-1003",
      2,
      "Especialista em Usinagem",
      "TAG-003",
      "DIG-003"
    ]);
    await run("INSERT INTO funcionarios(nome,matricula,area_id,cargo,dispositivo_id,digital_id) VALUES(?,?,?,?,?,?)", [
      "Fernanda Costa Ramos",
      "SEN-1004",
      3,
      "Docente de Eletroeletrônica",
      "TAG-004",
      "DIG-004"
    ]);
  } else {
    // Garante que os professores base tenham IDs biométricos preenchidos
    await run("UPDATE funcionarios SET digital_id='DIG-001' WHERE matricula='SEN-1001' AND (digital_id IS NULL OR digital_id='')");
    await run("UPDATE funcionarios SET digital_id='DIG-002' WHERE matricula='SEN-1002' AND (digital_id IS NULL OR digital_id='')");
    await run("UPDATE funcionarios SET digital_id='DIG-003' WHERE matricula='SEN-1003' AND (digital_id IS NULL OR digital_id='')");
    await run("UPDATE funcionarios SET digital_id='DIG-004' WHERE matricula='SEN-1004' AND (digital_id IS NULL OR digital_id='')");
  }

  const kCount = await get("SELECT count(*) n FROM chaves");
  if (!kCount || kCount.n === 0) {
    await run("INSERT INTO chaves(codigo,sala_id,status) VALUES(?,?,?)", ["CH-SL01", 1, "Disponível"]);
    await run("INSERT INTO chaves(codigo,sala_id,status) VALUES(?,?,?)", ["CH-SL02", 2, "Disponível"]);
    await run("INSERT INTO chaves(codigo,sala_id,status) VALUES(?,?,?)", ["CH-LAB01", 3, "Disponível"]);
  }

  const aCount = await get("SELECT count(*) n FROM acessos");
  if (!aCount || aCount.n === 0) {
    await run("INSERT INTO acessos(funcionario_id,tipo,origem,dispositivo_id) VALUES(?,?,?,?)", [
      1,
      "entrada",
      "Leitor Biométrico Digital",
      "DIG-001",
    ]);
    await run("INSERT INTO acessos(funcionario_id,tipo,origem,dispositivo_id) VALUES(?,?,?,?)", [
      2,
      "entrada",
      "Leitor Biométrico Digital",
      "DIG-002",
    ]);
  }

  // Semente de agendamentos de salas para demonstração
  const agCount = await get("SELECT count(*) n FROM agendamentos_salas");
  if (!agCount || agCount.n === 0) {
    const today = new Date().toISOString().split("T")[0];
    const salasDisponiveis = await all("SELECT id, nome FROM salas ORDER BY id LIMIT 3");
    if (salasDisponiveis && salasDisponiveis.length > 0) {
      await run(`INSERT INTO agendamentos_salas(sala_id, funcionario_id, solicitante_nome, data, hora_inicio, hora_fim, disciplina_motivo, turno, status, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?)`, [
        salasDisponiveis[0].id, 1, "Carlos Eduardo Silva", today, "08:00", "11:30", "Instalações Elétricas Industriais", "Manhã", "Confirmado", "Turma Eletrotécnica 2026.1"
      ]);
      if (salasDisponiveis.length > 1) {
        await run(`INSERT INTO agendamentos_salas(sala_id, funcionario_id, solicitante_nome, data, hora_inicio, hora_fim, disciplina_motivo, turno, status, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?)`, [
          salasDisponiveis[1].id, 4, "Fernanda Costa Ramos", today, "13:30", "17:00", "Química Aplicada e Automação", "Tarde", "Confirmado", "Prática em Bancada"
        ]);
      }
    }
  }

  // Semente de veículos para demonstração do módulo de controle de veículos
  const vCount = await get("SELECT count(*) n FROM veiculos");
  if (!vCount || vCount.n === 0) {
    const nowIso = new Date().toISOString();
    await run(`INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, [
      "BRA2E19", "Toyota Corolla XEi", "Preto Ônix", "Carro", "Arthur César Amorim Santos", "Professor", 1, "Vaga A-01 (Docentes)", "Ocupado", nowIso, "Professor de Robótica e Mecatrônica - Veículo no Pátio"
    ]);
    await run(`INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, [
      "SEN1001", "Honda Civic EXL", "Prata Metálico", "Carro", "Carlos Eduardo Silva", "Professor", 1, "Vaga A-02 (Docentes)", "Ocupado", nowIso, "Instrutor de TI - Veículo no Pátio"
    ]);
    await run(`INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, saida_hora, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, [
      "ABC4F88", "Fiat Toro Ranch", "Branca Polar", "Utilitário", "Roberto Oliveira Lima", "Professor", 3, "Vaga B-04", "Disponível", null, nowIso, "Especialista em Usinagem Mecânica"
    ]);
    await run(`INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, [
      "KRT9021", "Hyundai HB20 Platinum", "Cinza Silk", "Carro", "Mariana Souza Santos", "Coordenação", 2, "Vaga C-01 (Coordenação)", "Ocupado", nowIso, "Coordenadora Pedagógica - Veículo no Pátio"
    ]);
    await run(`INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, saida_hora, observacoes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, [
      "MOT7A12", "Honda CB 500F", "Vermelha Perolizada", "Moto", "Fernanda Costa Ramos", "Docente", 4, "Vaga Moto M-01", "Disponível", null, nowIso, "Docente de Eletroeletrônica"
    ]);
  }
}

// --------------------------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// --------------------------------------------------------------------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, senha } = req.body || {};
    if (!email || !senha) {
      return res.status(400).json({ erro: "E-mail e senha são obrigatórios" });
    }
    const u = await get("SELECT * FROM usuarios WHERE email=?", [email.trim().toLowerCase()]);
    if (!u || !(await bcrypt.compare(senha, u.senha_hash))) {
      return res.status(401).json({ erro: "Credenciais de acesso incorretas" });
    }
    const token = jwt.sign({ id: u.id, perfil: u.perfil }, SECRET, { expiresIn: "8h" });
    res.json({ token, nome: u.nome, perfil: u.perfil });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao processar login: " + e.message });
  }
});

// --------------------------------------------------------------------------
// DASHBOARD & VISÃO GERAL
// --------------------------------------------------------------------------
app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const f = await get("SELECT count(*) n FROM funcionarios WHERE ativo=1");
    const sTot = await get("SELECT count(*) n FROM salas");
    const s = await get("SELECT count(*) n FROM salas WHERE status='Disponível'");
    const kTot = await get("SELECT count(*) n FROM chaves");
    const k = await get("SELECT count(*) n FROM chaves WHERE status='Disponível'");
    const a = await get(
      "SELECT count(*) n FROM acessos WHERE date(data_hora, 'localtime') = date('now', 'localtime')"
    );
    const recents = await all(`
      SELECT a.*, f.nome funcionario, ar.nome area
      FROM acessos a
      LEFT JOIN funcionarios f ON f.id=a.funcionario_id
      LEFT JOIN areas ar ON ar.id=f.area_id
      ORDER BY a.id DESC
      LIMIT 6
    `);

    res.json({
      funcionarios: f ? f.n : 0,
      salasDisponiveis: s ? s.n : 0,
      salasTotal: sTot ? sTot.n : 0,
      chavesDisponiveis: k ? k.n : 0,
      chavesTotal: kTot ? kTot.n : 0,
      acessosHoje: a ? a.n : 0,
      ultimosAcessos: recents || [],
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao carregar dados do dashboard: " + e.message });
  }
});

// --------------------------------------------------------------------------
// ÁREAS
// --------------------------------------------------------------------------
app.get("/api/areas", auth, async (req, res) => {
  try {
    const areas = await all("SELECT * FROM areas ORDER BY nome");
    res.json(areas);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// FUNCIONÁRIOS / PROFESSORES
// --------------------------------------------------------------------------
app.get("/api/funcionarios", auth, async (req, res) => {
  try {
    const rows = await all(`
      SELECT f.*, a.nome area
      FROM funcionarios f
      LEFT JOIN areas a ON a.id=f.area_id
      ORDER BY f.nome
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/funcionarios", auth, admin, async (req, res) => {
  try {
    const { nome, matricula, cargo, area_id, dispositivo_id, digital_id } = req.body || {};
    if (!nome || !nome.trim()) {
      return res.status(400).json({ erro: "Nome do funcionário é obrigatório" });
    }
    if (!matricula || !matricula.trim()) {
      return res.status(400).json({ erro: "Matrícula é obrigatória" });
    }

    const dispId = dispositivo_id && dispositivo_id.trim() !== "" ? dispositivo_id.trim() : null;
    const digId = digital_id && digital_id.trim() !== "" ? digital_id.trim() : null;
    const areaId = area_id ? Number(area_id) : null;

    const result = await run(
      "INSERT INTO funcionarios(nome,matricula,area_id,cargo,dispositivo_id,digital_id) VALUES(?,?,?,?,?,?)",
      [nome.trim(), matricula.trim(), areaId, cargo ? cargo.trim() : "", dispId, digId]
    );
    res.json({ id: result.id, ok: true });
  } catch (e) {
    if (e.message && e.message.includes("UNIQUE constraint failed: funcionarios.matricula")) {
      return res.status(400).json({ erro: "Já existe um funcionário com esta matrícula." });
    }
    if (e.message && e.message.includes("UNIQUE constraint failed: funcionarios.dispositivo_id")) {
      return res.status(400).json({ erro: "Este crachá/dispositivo RFID já está cadastrado para outro funcionário." });
    }
    if (e.message && e.message.includes("idx_func_digital")) {
      return res.status(400).json({ erro: "Esta impressão digital já está cadastrada para outro colaborador." });
    }
    res.status(400).json({ erro: e.message });
  }
});

app.delete("/api/funcionarios/:id", auth, admin, async (req, res) => {
  try {
    const funcId = req.params.id;
    const chavesEmUso = await get(
      "SELECT count(*) n FROM retiradas_chaves WHERE funcionario_id=? AND devolucao IS NULL",
      [funcId]
    );
    if (chavesEmUso && chavesEmUso.n > 0) {
      return res.status(400).json({
        erro: "Não é possível excluir: o colaborador possui chaves retiradas que ainda não foram devolvidas.",
      });
    }

    await run("DELETE FROM funcionarios WHERE id=?", [funcId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// SALAS & LABORATÓRIOS
// --------------------------------------------------------------------------
app.get("/api/salas", auth, async (req, res) => {
  try {
    const salas = await all("SELECT * FROM salas ORDER BY nome");
    res.json(salas);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/salas", auth, admin, async (req, res) => {
  try {
    const { nome, capacidade } = req.body || {};
    if (!nome || !nome.trim()) {
      return res.status(400).json({ erro: "Nome da sala é obrigatório" });
    }
    const cap = Math.max(0, parseInt(capacidade, 10) || 0);

    const result = await run("INSERT INTO salas(nome,capacidade,status) VALUES(?,?,?)", [
      nome.trim(),
      cap,
      "Disponível",
    ]);
    res.json({ id: result.id, ok: true });
  } catch (e) {
    if (e.message && e.message.includes("UNIQUE")) {
      return res.status(400).json({ erro: "Já existe uma sala cadastrada com este nome." });
    }
    res.status(400).json({ erro: e.message });
  }
});

app.patch("/api/salas/:id", auth, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!status || !["Disponível", "Ocupada", "Manutenção"].includes(status)) {
      return res.status(400).json({ erro: "Status inválido fornecido" });
    }
    await run("UPDATE salas SET status=? WHERE id=?", [status, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

app.delete("/api/salas/:id", auth, admin, async (req, res) => {
  try {
    const salaId = req.params.id;
    const chavesCount = await get("SELECT count(*) n FROM chaves WHERE sala_id=?", [salaId]);
    if (chavesCount && chavesCount.n > 0) {
      return res.status(400).json({
        erro: `Não é possível remover a sala: existe(m) ${chavesCount.n} chave(s) vinculada(s) a ela.`,
      });
    }

    await run("DELETE FROM salas WHERE id=?", [salaId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// AGENDAMENTO DE SALAS & LABORATÓRIOS
// --------------------------------------------------------------------------
app.get("/api/agendamentos", auth, async (req, res) => {
  try {
    const { sala_id, data, status } = req.query || {};
    let query = `
      SELECT a.*, s.nome as sala_nome, s.capacidade as sala_capacidade,
             f.nome as funcionario_nome, f.cargo as funcionario_cargo, f.matricula as funcionario_matricula,
             ar.nome as funcionario_area
      FROM agendamentos_salas a
      JOIN salas s ON s.id = a.sala_id
      LEFT JOIN funcionarios f ON f.id = a.funcionario_id
      LEFT JOIN areas ar ON ar.id = f.area_id
      WHERE 1=1
    `;
    const params = [];
    if (sala_id) {
      query += ` AND a.sala_id = ?`;
      params.push(sala_id);
    }
    if (data) {
      query += ` AND a.data = ?`;
      params.push(data);
    }
    if (status) {
      query += ` AND a.status = ?`;
      params.push(status);
    }
    query += ` ORDER BY a.data DESC, a.hora_inicio ASC`;
    const rows = await all(query, params);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.get("/api/salas/:id/agendamentos", auth, async (req, res) => {
  try {
    const salaId = req.params.id;
    const rows = await all(`
      SELECT a.*, s.nome as sala_nome, f.nome as funcionario_nome
      FROM agendamentos_salas a
      JOIN salas s ON s.id = a.sala_id
      LEFT JOIN funcionarios f ON f.id = a.funcionario_id
      WHERE a.sala_id = ?
      ORDER BY a.data DESC, a.hora_inicio ASC
    `, [salaId]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/agendamentos", auth, async (req, res) => {
  try {
    const {
      sala_id,
      funcionario_id,
      solicitante_nome,
      data,
      hora_inicio,
      hora_fim,
      disciplina_motivo,
      turno,
      observacoes
    } = req.body || {};

    if (!sala_id) {
      return res.status(400).json({ erro: "Selecione o ambiente para agendamento." });
    }
    if (!data) {
      return res.status(400).json({ erro: "Data do agendamento é obrigatória." });
    }
    if (!hora_inicio || !hora_fim) {
      return res.status(400).json({ erro: "Horário de início e término são obrigatórios." });
    }
    if (hora_inicio >= hora_fim) {
      return res.status(400).json({ erro: "Horário de início deve ser anterior ao horário de término." });
    }
    if (!disciplina_motivo || !disciplina_motivo.trim()) {
      return res.status(400).json({ erro: "Informe a disciplina, aula ou motivo do agendamento." });
    }

    // Identificação do solicitante
    let nomeFinal = (solicitante_nome || "").trim();
    if (funcionario_id && !nomeFinal) {
      const func = await get("SELECT nome FROM funcionarios WHERE id=?", [funcionario_id]);
      if (func) nomeFinal = func.nome;
    }
    if (!nomeFinal) {
      nomeFinal = (req.user && req.user.nome) ? req.user.nome : "Docente / Responsável";
    }

    // Detecção Inteligente de Conflito de Horário
    // Conflito ocorre se a mesma sala na mesma data possui reserva ativa que se sobreponha
    const conflito = await get(`
      SELECT a.*, s.nome as sala_nome
      FROM agendamentos_salas a
      JOIN salas s ON s.id = a.sala_id
      WHERE a.sala_id = ?
        AND a.data = ?
        AND a.status NOT IN ('Cancelado')
        AND (a.hora_inicio < ? AND a.hora_fim > ?)
      LIMIT 1
    `, [sala_id, data, hora_fim, hora_inicio]);

    if (conflito) {
      return res.status(400).json({
        erro: `Conflito de Horário: a sala "${conflito.sala_nome}" já está agendada para "${conflito.solicitante_nome}" (${conflito.disciplina_motivo}) no intervalo das ${conflito.hora_inicio} às ${conflito.hora_fim}.`
      });
    }

    const result = await run(`
      INSERT INTO agendamentos_salas(
        sala_id, funcionario_id, solicitante_nome, data, hora_inicio, hora_fim,
        disciplina_motivo, turno, status, observacoes
      ) VALUES(?,?,?,?,?,?,?,?,?,?)
    `, [
      sala_id,
      funcionario_id || null,
      nomeFinal,
      data,
      hora_inicio,
      hora_fim,
      disciplina_motivo.trim(),
      turno || "Manhã",
      "Confirmado",
      observacoes ? observacoes.trim() : null
    ]);

    res.json({ id: result.id, ok: true, mensagem: "Agendamento registrado com sucesso!" });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.patch("/api/agendamentos/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body || {};
    const valid = ["Confirmado", "Em Andamento", "Concluído", "Cancelado"];
    if (!status || !valid.includes(status)) {
      return res.status(400).json({ erro: "Status inválido fornecido." });
    }
    await run("UPDATE agendamentos_salas SET status=? WHERE id=?", [status, req.params.id]);
    res.json({ ok: true, mensagem: `Status atualizado para "${status}".` });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.delete("/api/agendamentos/:id", auth, async (req, res) => {
  try {
    await run("DELETE FROM agendamentos_salas WHERE id=?", [req.params.id]);
    res.json({ ok: true, mensagem: "Agendamento excluído com sucesso." });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// CONTROLE DE VEÍCULOS & ESTACIONAMENTO
// --------------------------------------------------------------------------
app.get("/api/veiculos", auth, async (req, res) => {
  try {
    const { q, status } = req.query || {};
    let sql = `
      SELECT v.*, f.nome as funcionario_nome, f.cargo as funcionario_cargo, f.matricula as funcionario_matricula
      FROM veiculos v
      LEFT JOIN funcionarios f ON f.id = v.funcionario_id
      WHERE 1=1
    `;
    const params = [];
    if (status) {
      sql += " AND v.status = ?";
      params.push(status);
    }
    if (q) {
      const term = `%${q.trim()}%`;
      const cleanPlate = `%${q.trim().toUpperCase().replace(/[^A-Z0-9]/g, "")}%`;
      sql += " AND (v.placa LIKE ? OR v.modelo LIKE ? OR v.motorista_nome LIKE ? OR REPLACE(REPLACE(v.placa, '-', ''), ' ', '') LIKE ?)";
      params.push(term, term, term, cleanPlate);
    }
    sql += " ORDER BY CASE WHEN v.status = 'Ocupado' THEN 0 ELSE 1 END, v.id DESC";

    const veiculos = await all(sql, params);
    res.json(veiculos || []);
  } catch (e) {
    res.status(500).json({ erro: "Erro ao listar veículos: " + e.message });
  }
});

app.get("/api/veiculos/consultar/:placa", auth, async (req, res) => {
  try {
    const rawPlaca = (req.params.placa || "").trim().toUpperCase();
    if (!rawPlaca) {
      return res.status(400).json({ erro: "Placa não informada para consulta." });
    }
    const cleanPlate = rawPlaca.replace(/[^A-Z0-9]/g, "");

    const veiculo = await get(`
      SELECT v.*, f.nome as funcionario_nome, f.cargo as funcionario_cargo, f.matricula as funcionario_matricula
      FROM veiculos v
      LEFT JOIN funcionarios f ON f.id = v.funcionario_id
      WHERE REPLACE(REPLACE(UPPER(v.placa), '-', ''), ' ', '') = ?
         OR UPPER(v.placa) = ?
      LIMIT 1
    `, [cleanPlate, rawPlaca]);

    if (!veiculo) {
      return res.json({
        encontrado: false,
        placa: rawPlaca,
        mensagem: "Veículo não cadastrado no sistema."
      });
    }

    const isOcupado = (veiculo.status === "Ocupado");
    res.json({
      encontrado: true,
      ocupado: isOcupado,
      status: veiculo.status,
      alerta_status: isOcupado ? "ESSE VEÍCULO ESTÁ OCUPADO" : "VEÍCULO DISPONÍVEL / LIBERADO",
      mensagem: isOcupado ? "ESSE VEÍCULO ESTÁ OCUPADO" : "Veículo cadastrado e liberado fora do pátio.",
      veiculo
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao consultar veículo: " + e.message });
  }
});

app.get("/api/veiculos/resumo", auth, async (req, res) => {
  try {
    const total = await get("SELECT count(*) n FROM veiculos");
    const ocupados = await get("SELECT count(*) n FROM veiculos WHERE status='Ocupado'");
    const disponiveis = await get("SELECT count(*) n FROM veiculos WHERE status='Disponível'");

    const nTotal = total ? total.n : 0;
    const nOcupados = ocupados ? ocupados.n : 0;
    const nDisponiveis = disponiveis ? disponiveis.n : 0;
    const CAPACIDADE_MAXIMA = 25; // 25 vagas no pátio interno do SENAI
    const vagasLivres = Math.max(0, CAPACIDADE_MAXIMA - nOcupados);
    const taxaOcupacao = Math.min(100, Math.round((nOcupados / CAPACIDADE_MAXIMA) * 100));

    res.json({
      total: nTotal,
      ocupados: nOcupados,
      disponiveis: nDisponiveis,
      capacidadeTotal: CAPACIDADE_MAXIMA,
      vagasRestantes: vagasLivres,
      taxaOcupacao: taxaOcupacao
    });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/veiculos", auth, async (req, res) => {
  try {
    const {
      placa,
      modelo,
      cor,
      tipo = "Carro",
      motorista_nome,
      categoria = "Professor",
      funcionario_id = null,
      vaga = "Pátio Principal",
      status = "Ocupado",
      observacoes = ""
    } = req.body || {};

    if (!placa || !placa.trim()) {
      return res.status(400).json({ erro: "A placa do veículo é obrigatória." });
    }
    if (!motorista_nome || !motorista_nome.trim()) {
      return res.status(400).json({ erro: "O nome do motorista/responsável é obrigatório." });
    }
    if (!modelo || !modelo.trim()) {
      return res.status(400).json({ erro: "O modelo do veículo é obrigatório." });
    }

    const placaNorm = placa.trim().toUpperCase();

    // Validação de Placa Duplicada
    const cleanPlate = placaNorm.replace(/[^A-Z0-9]/g, "");
    const existe = await get(`
      SELECT id, motorista_nome, modelo FROM veiculos 
      WHERE REPLACE(REPLACE(UPPER(placa), '-', ''), ' ', '') = ?
    `, [cleanPlate]);

    if (existe) {
      return res.status(400).json({
        erro: `A placa "${placaNorm}" já está cadastrada no sistema para o veículo ${existe.modelo} (${existe.motorista_nome}).`
      });
    }

    // Validação de Vaga Ocupada (Prevenção de Erros - Heurística 5)
    let avisoVaga = null;
    if (status === "Ocupado" && vaga && vaga.trim() && vaga.trim() !== "Pátio Principal") {
      const vagaOcupada = await get(`
        SELECT id, placa, modelo, motorista_nome 
        FROM veiculos 
        WHERE status='Ocupado' AND LOWER(vaga)=LOWER(?)
      `, [vaga.trim()]);
      if (vagaOcupada) {
        avisoVaga = `Aviso: A vaga "${vaga.trim()}" já está ocupada por [${vagaOcupada.placa} - ${vagaOcupada.modelo}].`;
      }
    }

    const nowIso = new Date().toISOString();
    const entradaHora = (status === "Ocupado") ? nowIso : null;

    const result = await run(`
      INSERT INTO veiculos(placa, modelo, cor, tipo, motorista_nome, categoria, funcionario_id, vaga, status, entrada_hora, observacoes)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    `, [
      placaNorm,
      modelo.trim(),
      (cor || "").trim(),
      tipo,
      motorista_nome.trim(),
      categoria,
      funcionario_id || null,
      vaga ? vaga.trim() : "Pátio Principal",
      status,
      entradaHora,
      (observacoes || "").trim()
    ]);

    if (status === "Ocupado") {
      await run(`
        INSERT INTO veiculos_movimentacoes(veiculo_id, placa, tipo_movimentacao, vaga, data_hora, usuario)
        VALUES(?, ?, 'entrada', ?, ?, ?)
      `, [result.id, placaNorm, vaga || "Pátio", nowIso, (req.user && req.user.nome) || "Administrador"]);
    }

    res.json({
      id: result.id,
      ok: true,
      mensagem: `Veículo [${placaNorm}] cadastrado com sucesso!`,
      placa: placaNorm,
      status,
      avisoVaga
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao cadastrar veículo: " + e.message });
  }
});

// Atualizar Veículo Cadastrado (Heurística 3 - Controle e Liberdade)
app.put("/api/veiculos/:id", auth, async (req, res) => {
  try {
    const {
      placa,
      modelo,
      cor,
      tipo = "Carro",
      motorista_nome,
      categoria = "Professor",
      vaga = "Pátio Principal",
      observacoes = ""
    } = req.body || {};

    const veiculoId = req.params.id;
    const existente = await get("SELECT * FROM veiculos WHERE id=?", [veiculoId]);
    if (!existente) {
      return res.status(404).json({ erro: "Veículo não encontrado." });
    }

    if (!placa || !placa.trim()) {
      return res.status(400).json({ erro: "A placa do veículo é obrigatória." });
    }
    if (!motorista_nome || !motorista_nome.trim()) {
      return res.status(400).json({ erro: "O nome do motorista/responsável é obrigatório." });
    }
    if (!modelo || !modelo.trim()) {
      return res.status(400).json({ erro: "O modelo do veículo é obrigatório." });
    }

    const placaNorm = placa.trim().toUpperCase();
    const cleanPlate = placaNorm.replace(/[^A-Z0-9]/g, "");

    // Prevenção de duplicidade com outro veículo
    const duplicado = await get(`
      SELECT id, motorista_nome, modelo FROM veiculos 
      WHERE REPLACE(REPLACE(UPPER(placa), '-', ''), ' ', '') = ?
        AND id != ?
    `, [cleanPlate, veiculoId]);

    if (duplicado) {
      return res.status(400).json({
        erro: `A placa "${placaNorm}" já pertence ao veículo [${duplicado.modelo}] de "${duplicado.motorista_nome}".`
      });
    }

    await run(`
      UPDATE veiculos 
      SET placa=?, modelo=?, cor=?, tipo=?, motorista_nome=?, categoria=?, vaga=?, observacoes=?
      WHERE id=?
    `, [
      placaNorm,
      modelo.trim(),
      (cor || "").trim(),
      tipo,
      motorista_nome.trim(),
      categoria,
      vaga ? vaga.trim() : "Pátio Principal",
      (observacoes || "").trim(),
      veiculoId
    ]);

    res.json({
      ok: true,
      mensagem: `Veículo [${placaNorm}] atualizado com sucesso!`,
      placa: placaNorm
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao atualizar veículo: " + e.message });
  }
});

// Desfazer Última Movimentação (Heurística 3 - Controle e Liberdade / Desfazer)
app.post("/api/veiculos/:id/desfazer", auth, async (req, res) => {
  try {
    const veiculoId = req.params.id;
    const veiculo = await get("SELECT * FROM veiculos WHERE id=?", [veiculoId]);
    if (!veiculo) {
      return res.status(404).json({ erro: "Veículo não encontrado." });
    }

    const novoStatus = (veiculo.status === "Ocupado") ? "Disponível" : "Ocupado";
    const nowIso = new Date().toISOString();

    if (novoStatus === "Ocupado") {
      await run("UPDATE veiculos SET status='Ocupado', entrada_hora=? WHERE id=?", [nowIso, veiculoId]);
    } else {
      await run("UPDATE veiculos SET status='Disponível', saida_hora=? WHERE id=?", [nowIso, veiculoId]);
    }

    // Remove a última movimentação registrada no log
    await run(`
      DELETE FROM veiculos_movimentacoes 
      WHERE id = (SELECT id FROM veiculos_movimentacoes WHERE veiculo_id=? ORDER BY id DESC LIMIT 1)
    `, [veiculoId]);

    res.json({
      ok: true,
      novoStatus,
      mensagem: `Ação desfeita com sucesso! Status do veículo [${veiculo.placa}] retornado para "${novoStatus}".`
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao desfazer movimentação: " + e.message });
  }
});

// Histórico de Movimentações do Veículo (Heurística 6 - Reconhecimento)
app.get("/api/veiculos/:id/historico", auth, async (req, res) => {
  try {
    const veiculoId = req.params.id;
    const historico = await all(`
      SELECT * FROM veiculos_movimentacoes 
      WHERE veiculo_id=? 
      ORDER BY id DESC LIMIT 15
    `, [veiculoId]);
    res.json(historico || []);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/veiculos/:id/movimentar", auth, async (req, res) => {
  try {
    const { acao, vaga } = req.body || {};
    const veiculo = await get("SELECT * FROM veiculos WHERE id=?", [req.params.id]);
    if (!veiculo) {
      return res.status(404).json({ erro: "Veículo não encontrado." });
    }

    const nowIso = new Date().toISOString();
    const usuarioNome = (req.user && req.user.nome) ? req.user.nome : "Operador";

    if (acao === "entrada") {
      const novaVaga = vaga && vaga.trim() ? vaga.trim() : (veiculo.vaga || "Pátio Principal");

      // Verificação de Vaga já Ocupada (Prevenção de Erros - Heurística 5)
      let avisoVaga = null;
      if (novaVaga !== "Pátio Principal") {
        const conflitoVaga = await get(`
          SELECT id, placa, modelo FROM veiculos 
          WHERE status='Ocupado' AND LOWER(vaga)=LOWER(?) AND id != ?
        `, [novaVaga, req.params.id]);
        if (conflitoVaga) {
          avisoVaga = `Atenção: A vaga "${novaVaga}" já está sendo utilizada por [${conflitoVaga.placa} - ${conflitoVaga.modelo}].`;
        }
      }

      await run("UPDATE veiculos SET status='Ocupado', entrada_hora=?, vaga=? WHERE id=?", [
        nowIso,
        novaVaga,
        req.params.id
      ]);

      await run(`
        INSERT INTO veiculos_movimentacoes(veiculo_id, placa, tipo_movimentacao, vaga, data_hora, usuario)
        VALUES(?, ?, 'entrada', ?, ?, ?)
      `, [req.params.id, veiculo.placa, novaVaga, nowIso, usuarioNome]);

      return res.json({
        ok: true,
        status: "Ocupado",
        alerta_status: "ESSE VEÍCULO ESTÁ OCUPADO",
        mensagem: `Entrada registrada! Veículo [${veiculo.placa}] agora está OCUPADO no pátio.`,
        avisoVaga
      });
    } else if (acao === "saida") {
      await run("UPDATE veiculos SET status='Disponível', saida_hora=? WHERE id=?", [
        nowIso,
        req.params.id
      ]);

      await run(`
        INSERT INTO veiculos_movimentacoes(veiculo_id, placa, tipo_movimentacao, vaga, data_hora, usuario)
        VALUES(?, ?, 'saida', ?, ?, ?)
      `, [req.params.id, veiculo.placa, veiculo.vaga || "Pátio", nowIso, usuarioNome]);

      return res.json({
        ok: true,
        status: "Disponível",
        mensagem: `Saída registrada! Veículo [${veiculo.placa}] liberado e vaga desocupada.`
      });
    } else {
      return res.status(400).json({ erro: "Ação inválida. Use 'entrada' ou 'saida'." });
    }
  } catch (e) {
    res.status(500).json({ erro: "Erro ao movimentar veículo: " + e.message });
  }
});

app.delete("/api/veiculos/:id", auth, async (req, res) => {
  try {
    const veiculo = await get("SELECT placa, modelo, motorista_nome FROM veiculos WHERE id=?", [req.params.id]);
    await run("DELETE FROM veiculos WHERE id=?", [req.params.id]);
    res.json({
      ok: true,
      mensagem: `Veículo [${veiculo ? veiculo.placa : ''}] removido com sucesso.`
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao excluir veículo: " + e.message });
  }
});

// --------------------------------------------------------------------------
// CHAVES
// --------------------------------------------------------------------------
app.get("/api/chaves", auth, async (req, res) => {
  try {
    const chaves = await all(`
      SELECT 
        c.*,
        COALESCE(s.nome, 'Ambiente Geral') as sala,
        f.nome responsavel,
        r.retirada,
        r.devolucao,
        CASE WHEN c.status = 'Atrasado' THEN 'Atrasado'
             WHEN c.status = 'Disponível' THEN 'Disponível'
             WHEN r.id IS NOT NULL AND r.devolucao IS NULL THEN 'Não Entregue'
             WHEN r.id IS NOT NULL AND r.devolucao IS NOT NULL THEN 'Entregue'
             ELSE c.status
        END as status_entrega
      FROM chaves c
      LEFT JOIN salas s ON s.id=c.sala_id
      LEFT JOIN retiradas_chaves r ON r.chave_id=c.id AND r.devolucao IS NULL
      LEFT JOIN funcionarios f ON f.id=r.funcionario_id
      ORDER BY c.codigo COLLATE NOCASE
    `);
    res.json(chaves);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post("/api/chaves", auth, admin, async (req, res) => {
  try {
    const { codigo, sala_id } = req.body || {};
    if (!codigo || !codigo.trim()) {
      return res.status(400).json({ erro: "Código identificador da chave é obrigatório" });
    }
    if (!sala_id) {
      return res.status(400).json({ erro: "Selecione a sala correspondente" });
    }

    const sala = await get("SELECT id FROM salas WHERE id=?", [sala_id]);
    if (!sala) {
      return res.status(404).json({ erro: "Sala informada não foi encontrada" });
    }

    const result = await run("INSERT INTO chaves(codigo,sala_id,status) VALUES(?,?,?)", [
      codigo.trim().toUpperCase(),
      sala_id,
      "Disponível",
    ]);
    res.json({ id: result.id, ok: true });
  } catch (e) {
    if (e.message && e.message.includes("UNIQUE")) {
      return res.status(400).json({ erro: "Já existe uma chave cadastrada com este código." });
    }
    res.status(400).json({ erro: e.message });
  }
});

app.delete("/api/chaves/:id", auth, admin, async (req, res) => {
  try {
    const keyId = req.params.id;
    const key = await get("SELECT * FROM chaves WHERE id=?", [keyId]);
    if (!key) return res.status(404).json({ erro: "Chave não encontrada" });

    if (key.status !== "Disponível") {
      return res.status(400).json({
        erro: "Não é possível excluir uma chave em uso ou atrasada. Registre a devolução antes de excluir.",
      });
    }

    await run("DELETE FROM retiradas_chaves WHERE chave_id=?", [keyId]);
    await run("DELETE FROM chaves WHERE id=?", [keyId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

app.post("/api/chaves/:id/retirar", auth, async (req, res) => {
  try {
    const keyId = req.params.id;
    const { funcionario_id } = req.body || {};

    if (!funcionario_id) {
      return res.status(400).json({ erro: "Funcionário solicitante é obrigatório" });
    }

    const c = await get("SELECT * FROM chaves WHERE id=?", [keyId]);
    if (!c) return res.status(404).json({ erro: "Chave não encontrada." });
    if (c.status !== "Disponível") {
      return res.status(400).json({ erro: "Esta chave já está em uso ou indisponível." });
    }

    const f = await get("SELECT id FROM funcionarios WHERE id=? AND ativo=1", [funcionario_id]);
    if (!f) return res.status(404).json({ erro: "Funcionário selecionado não foi encontrado ou está inativo." });

    // Generate alphanumeric code for the withdrawal
    const alfanum = `${keyId}-${Date.now().toString(36).toUpperCase()}`;
    // A atualização condicional evita que duas requisições simultâneas
    // retirem a mesma chave (corrida entre a leitura e a escrita).
    const update = await run(
      "UPDATE chaves SET status='Em uso', codigo_alfanumerico=? WHERE id=? AND status='Disponível'",
      [alfanum, keyId]
    );

    if (update.changes === 0) {
      return res.status(409).json({ erro: "Esta chave acabou de ser retirada por outro usuário. Atualize a listagem." });
    }

    await run("INSERT INTO retiradas_chaves(chave_id,funcionario_id) VALUES(?,?)", [
      keyId,
      funcionario_id,
    ]);
    res.json({ ok: true, codigo_alfanumerico: alfanum });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

app.post("/api/chaves/:id/devolver", auth, async (req, res) => {
  try {
    const keyId = req.params.id;
    const c = await get("SELECT * FROM chaves WHERE id=?", [keyId]);
    if (!c) return res.status(404).json({ erro: "Chave não encontrada." });
    if (c.status === "Disponível") {
      return res.status(400).json({ erro: "Esta chave já está disponível no claviculário." });
    }

    const devolucao = await run(
      "UPDATE retiradas_chaves SET devolucao=CURRENT_TIMESTAMP WHERE chave_id=? AND devolucao IS NULL",
      [keyId]
    );

    if (devolucao.changes === 0) {
      return res.status(400).json({ erro: "Não há uma retirada em aberto para esta chave." });
    }

    await run("UPDATE chaves SET status='Disponível' WHERE id=?", [keyId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// LEITOR BIOMÉTRICO (RECONHECIMENTO DE PROFESSORES PELA DIGITAL)
// --------------------------------------------------------------------------
app.post("/api/biometria/identificar", async (req, res) => {
  try {
    const rawVal = (req.body && (req.body.digital_id || req.body.dispositivo_id || req.body.codigo)) || "";
    const digital_id = String(rawVal).trim();
    const funcionario_id = req.body && req.body.funcionario_id;

    if (!digital_id && !funcionario_id) {
      return res.status(400).json({ erro: "Impressão digital não detectada no sensor biométrico." });
    }

    let f = null;
    if (funcionario_id) {
      f = await get(`
        SELECT f.*, COALESCE(a.nome, 'Geral') as area 
        FROM funcionarios f 
        LEFT JOIN areas a ON a.id = f.area_id 
        WHERE f.id = ? AND f.ativo = 1
      `, [funcionario_id]);
    } else {
      f = await get(`
        SELECT f.*, COALESCE(a.nome, 'Geral') as area 
        FROM funcionarios f 
        LEFT JOIN areas a ON a.id = f.area_id 
        WHERE (f.digital_id = ? OR f.dispositivo_id = ? OR f.matricula = ?) AND f.ativo = 1
      `, [digital_id, digital_id, digital_id]);
    }

    if (!f) {
      return res.status(404).json({
        erro: "Digital não reconhecida. Professor ou colaborador não cadastrado na base biométrica."
      });
    }

    const tipo = (req.body.tipo || "entrada").toLowerCase();
    const origem = req.body.origem || "Leitor Biométrico (Digital)";

    await run("INSERT INTO acessos(funcionario_id,tipo,origem,dispositivo_id) VALUES(?,?,?,?)", [
      f.id,
      tipo,
      origem,
      f.digital_id || f.dispositivo_id || "BIOMETRIA",
    ]);

    res.json({
      identificado: true,
      professor: {
        id: f.id,
        nome: f.nome,
        area: f.area,
        cargo: f.cargo || "Professor / Instrutor",
        matricula: f.matricula,
        digital_id: f.digital_id || ("DIG-00" + f.id),
        dispositivo_id: f.dispositivo_id,
        tipo: tipo,
        origem: origem,
        data_hora: new Date().toISOString()
      }
    });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao processar biometria: " + e.message });
  }
});

app.get("/api/biometria/professores", async (req, res) => {
  try {
    const list = await all(`
      SELECT f.id, f.nome, f.matricula, f.cargo, f.digital_id, f.dispositivo_id, COALESCE(a.nome, 'Geral') as area
      FROM funcionarios f
      LEFT JOIN areas a ON a.id = f.area_id
      WHERE f.ativo = 1
      ORDER BY f.nome
    `);
    res.json(list);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Detecções genéricas (compatibilidade RFID + Digital)
app.post("/api/deteccoes", async (req, res) => {
  try {
    const rawDisp = (req.body && (req.body.dispositivo_id || req.body.digital_id)) || "";
    const idCode = rawDisp.trim();

    if (!idCode) {
      return res.status(400).json({ erro: "Identificador não informado" });
    }

    const f = await get(
      `SELECT f.*, COALESCE(a.nome, 'Geral') as area 
       FROM funcionarios f 
       LEFT JOIN areas a ON a.id=f.area_id 
       WHERE (f.dispositivo_id=? OR f.digital_id=? OR f.matricula=?) AND f.ativo=1`,
      [idCode, idCode, idCode]
    );

    if (!f) {
      return res.status(404).json({ erro: "Dispositivo ou biometria não cadastrada no sistema." });
    }

    const tipo = (req.body.tipo || "entrada").toLowerCase();
    const origem = req.body.origem || "detector";

    await run("INSERT INTO acessos(funcionario_id,tipo,origem,dispositivo_id) VALUES(?,?,?,?)", [
      f.id,
      tipo,
      origem,
      idCode,
    ]);

    res.json({ identificado: true, funcionario: f });
  } catch (e) {
    res.status(500).json({ erro: "Erro ao registrar detecção: " + e.message });
  }
});

app.get("/api/acessos", auth, async (req, res) => {
  try {
    const acessos = await all(`
      SELECT 
        a.*,
        f.nome funcionario,
        ar.nome area
      FROM acessos a
      LEFT JOIN funcionarios f ON f.id=a.funcionario_id
      LEFT JOIN areas ar ON ar.id=f.area_id
      ORDER BY a.id DESC
      LIMIT 500
    `);
    res.json(acessos);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// API COPED — Painel de chaves em ordem alfanumérica + status de entrega
// --------------------------------------------------------------------------
app.get("/api/coped/chaves", auth, adminOrCoped, async (req, res) => {
  try {
    const chaves = await all(`
      SELECT
        c.id,
        c.codigo,
        COALESCE(s.nome, 'Ambiente Geral') as sala,
        c.status,
        f.nome as responsavel,
        f.matricula,
        r.retirada,
        r.devolucao,
        CASE
          WHEN c.status = 'Atrasado' THEN 'Atrasado'
          WHEN c.status = 'Disponível' THEN 'Disponível'
          WHEN r.id IS NOT NULL AND r.devolucao IS NULL THEN 'Não Entregue'
          WHEN r.id IS NOT NULL AND r.devolucao IS NOT NULL THEN 'Entregue'
          ELSE c.status
        END as status_entrega
      FROM chaves c
      LEFT JOIN salas s ON s.id = c.sala_id
      LEFT JOIN retiradas_chaves r ON r.chave_id = c.id AND r.devolucao IS NULL
      LEFT JOIN funcionarios f ON f.id = r.funcionario_id
      ORDER BY c.codigo COLLATE NOCASE
    `);
    res.json(chaves);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.get("/api/coped/historico", auth, adminOrCoped, async (req, res) => {
  try {
    const historico = await all(`
      SELECT
        rc.id,
        c.codigo as chave,
        COALESCE(s.nome, 'Ambiente Geral') as sala,
        f.nome as responsavel,
        f.matricula,
        rc.retirada,
        rc.devolucao,
        CASE WHEN rc.devolucao IS NULL THEN 'Não Entregue' ELSE 'Entregue' END as status_entrega
      FROM retiradas_chaves rc
      JOIN chaves c ON c.id = rc.chave_id
      LEFT JOIN salas s ON s.id = c.sala_id
      LEFT JOIN funcionarios f ON f.id = rc.funcionario_id
      ORDER BY c.codigo COLLATE NOCASE, rc.retirada DESC
      LIMIT 500
    `);
    res.json(historico);
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.get("/api/coped/resumo", auth, adminOrCoped, async (req, res) => {
  try {
    const total    = await get("SELECT count(*) n FROM chaves");
    const emUso    = await get("SELECT count(*) n FROM chaves WHERE status='Em uso'");
    const disp     = await get("SELECT count(*) n FROM chaves WHERE status='Disponível'");
    const atraso   = await get("SELECT count(*) n FROM chaves WHERE status='Atrasado'");
    const entregues = await get("SELECT count(*) n FROM retiradas_chaves WHERE devolucao IS NOT NULL");
    const pendentes = await get("SELECT count(*) n FROM retiradas_chaves WHERE devolucao IS NULL");
    res.json({
      total:        total?.n    || 0,
      emUso:        emUso?.n    || 0,
      disponiveis:  disp?.n     || 0,
      atrasadas:    atraso?.n   || 0,
      entregues:    entregues?.n || 0,
      pendentes:    pendentes?.n || 0
    });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// --------------------------------------------------------------------------
// API PÚBLICA — disponibilidade de salas e chaves (sem dados pessoais)
// Consumida pelo monitor/tela do cliente, que pode ser aberta sem login.
// --------------------------------------------------------------------------
app.get("/api/public/salas", async (req, res) => {
  try {
    const [salas, chaves] = await Promise.all([
      all("SELECT id, nome, capacidade, status FROM salas ORDER BY nome"),
      all("SELECT id, codigo, sala_id, status FROM chaves ORDER BY codigo COLLATE NOCASE"),
    ]);

    const chavesPorSala = new Map();
    for (const chave of chaves) {
      const lista = chavesPorSala.get(chave.sala_id) || [];
      lista.push({ codigo: chave.codigo, status: chave.status });
      chavesPorSala.set(chave.sala_id, lista);
    }

    res.json({
      salas: salas.map((sala) => ({
        ...sala,
        chaves: chavesPorSala.get(sala.id) || [],
      })),
      resumo: {
        salasTotal: salas.length,
        salasDisponiveis: salas.filter((s) => s.status === "Disponível").length,
        chavesTotal: chaves.length,
        chavesDisponiveis: chaves.filter((c) => c.status === "Disponível").length,
        chavesEmUso: chaves.filter((c) => c.status === "Em uso").length,
        chavesAtrasadas: chaves.filter((c) => c.status === "Atrasado").length,
      },
      atualizadoEm: new Date().toISOString(),
    });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// SPA Fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Inicia banco e servidor
init().then(() => {
  // Periodic task to mark overdue keys (e.g., not returned after 2 days)
  const checkOverdue = async () => {
    try {
      const overdue = await all(`
        SELECT rc.id as retirada_id, rc.chave_id, rc.retirada
        FROM retiradas_chaves rc
        JOIN chaves c ON c.id = rc.chave_id
        WHERE rc.devolucao IS NULL AND datetime(rc.retirada) <= datetime('now', '-2 days')
      `);
      for (const row of overdue) {
        await run("UPDATE chaves SET status='Atrasado' WHERE id=?", [row.chave_id]);
      }
    } catch (e) {
      console.error('Erro ao checar chaves atrasadas:', e.message);
    }
  };
  // Run first check after server start and then every 24h
  checkOverdue();
  setInterval(checkOverdue, 24 * 60 * 60 * 1000);

  app.listen(PORT, () => console.log("SKyPort rodando em http://localhost:" + PORT));
});
