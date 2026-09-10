const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./geofrota.db', (err) => {
    if (err) console.error("Erro no banco:", err.message);
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS viaturas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefixo TEXT,
        placa TEXT,
        modelo TEXT,
        km INTEGER DEFAULT 0,
        km_revisao INTEGER DEFAULT 10000, 
        status TEXT DEFAULT 'Operante',
        ultimo_usuario TEXT DEFAULT 'Sistema'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        cargo TEXT
    )`, () => {
        db.get("SELECT count(*) as count FROM usuarios", (err, row) => {
            if (row && row.count === 0) {
                db.run("INSERT INTO usuarios (nome, cargo) VALUES (?, ?)", ['Administrador', 'Gestor']);
            }
        });
    });
});

module.exports = db;