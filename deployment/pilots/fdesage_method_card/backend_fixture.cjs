// Isolated verification only. The API child receives its restricted DB login,
// user-token key and identity map; owner setup credentials stay in this preparer.
const path = require('node:path')
const crypto = require('node:crypto')
const readline = require('node:readline')
const { fork } = require('node:child_process')
const fs = require('node:fs')
const backend = process.argv[2]
const { Sequelize } = require(path.join(backend, 'node_modules/sequelize'))
const open = (database, user, password, port) => new Sequelize(database, user, password, {
  host: '127.0.0.1', port, dialect: 'mysql', timezone: '+00:00', logging: false,
  pool: { max: 3, min: 0, idle: 1000 },
})

if (process.argv[3] === 'app') {
  process.once('message', async (packet) => {
    const db = open(packet.database, packet.user, packet.password, packet.port)
    try {
      const { createApp } = require(path.join(backend, 'src/app'))
      const app = createApp({ db, config: {
        nodeEnv: 'production', authTokenSecret: packet.secret,
        ainsMethodCards: { enabled: true, namespace: 'fdesage-ops', ttlSeconds: 900, actorBindings: packet.bindings },
      } })
      const server = app.listen(0, '127.0.0.1', () => process.send({ origin: `http://127.0.0.1:${server.address().port}` }))
      let stopping
      const stop = () => {
        if (!stopping) stopping = (async () => { await new Promise((resolve) => server.close(resolve)); await db.close(); process.exit(0) })()
        return stopping
      }
      process.once('message', stop)
      process.once('disconnect', stop)
      process.once('SIGTERM', stop)
    } catch { await db.close(); process.exit(1) }
  })
} else {
  const { buildDatabaseFromSchema } = require(path.join(backend, 'scripts/schemaLoader'))
  const { signUserToken } = require(path.join(backend, 'src/auth/token'))
  const privateConfig = JSON.parse(fs.readFileSync(process.env.FDE_METHOD_JOINT_PRIVATE_CONFIG))
  const tag = crypto.randomBytes(4).toString('hex')
  const database = `fdesage_method_joint_${tag}_test`
  const appUser = `method_app_${tag}`
  const sourceUser = `method_source_${tag}`
  const appPassword = crypto.randomBytes(24).toString('hex')
  const sourcePassword = crypto.randomBytes(24).toString('hex')
  const secret = crypto.randomBytes(32).toString('hex')
  const epoch = `method-joint-${tag}`
  const port = Number(privateConfig.mysqlPort)
  const administrator = open('mysql', 'root', privateConfig.mysqlPassword, port)
  let owner
  let child
  const output = (document) => process.stdout.write(JSON.stringify(document) + '\n')
  const one = async (sql, replacements = {}) => (await owner.query(sql, { replacements }))[0][0]
  async function grant(user, clauses) {
    for (const clause of clauses) await administrator.query(`GRANT ${clause} TO '${user}'@'%'`)
  }
  async function start() {
    const [[exists]] = await administrator.query('SELECT COUNT(*) AS n FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=:database', { replacements: { database } })
    if (Number(exists.n)) throw new Error('Refuse to overwrite an existing database')
    await buildDatabaseFromSchema({ host: '127.0.0.1', port, user: 'root', password: privateConfig.mysqlPassword, database })
    owner = open(database, 'root', privateConfig.mysqlPassword, port)
    for (const [user, password] of [[appUser, appPassword], [sourceUser, sourcePassword]]) {
      await administrator.query(`CREATE USER '${user}'@'%' IDENTIFIED BY ${administrator.escape(password)}`)
    }
    await grant(appUser, [
      `SELECT ON \`${database}\`.users`, `SELECT ON \`${database}\`.method_cards`,
      `UPDATE (verification_intent_id) ON \`${database}\`.method_cards`,
      `SELECT ON \`${database}\`.method_card_protection`, `SELECT ON \`${database}\`.method_card_source_state`,
      `UPDATE (namespace) ON \`${database}\`.method_card_source_state`,
      `SELECT, INSERT ON \`${database}\`.method_card_submissions`,
      `UPDATE (revoked_at) ON \`${database}\`.method_card_submissions`,
      `SELECT ON \`${database}\`.method_card_source_operations`,
    ])
    await grant(sourceUser, [
      ...['users', 'method_cards', 'method_card_source_state', 'method_card_protection', 'method_card_submissions', 'method_card_source_operations']
        .map((table) => `SELECT ON \`${database}\`.\`${table}\``),
      `UPDATE (namespace) ON \`${database}\`.method_card_source_state`,
      `UPDATE (id) ON \`${database}\`.method_card_submissions`,
      `UPDATE (review_status) ON \`${database}\`.method_cards`,
      `INSERT ON \`${database}\`.method_card_source_operations`,
      `UPDATE (receipt_json,signed_at) ON \`${database}\`.method_card_source_operations`,
      `INSERT ON \`${database}\`.method_card_source_audit`,
    ])
    const [requester] = await owner.query("INSERT INTO users (display_name,role) VALUES ('合成请求者','operator')")
    const [reviewer] = await owner.query("INSERT INTO users (display_name,role) VALUES ('合成独立审批者','operator')")
    const bindings = [requester, reviewer].map((id) => ({ userId: String(id), actor: `fde-operator:${id}`, service: null, delegationId: null }))
    await owner.query("INSERT INTO method_card_source_state(namespace,epoch,enabled) VALUES('fdesage-ops',:epoch,1)", { replacements: { epoch } })
    child = fork(__filename, [backend, 'app'], { env: { PATH: process.env.PATH }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
    const ready = new Promise((resolve, reject) => { child.once('message', resolve); child.once('exit', () => reject(new Error('API fixture exited'))) })
    child.send({ database, user: appUser, password: appPassword, port, secret, bindings })
    const { origin } = await ready
    output({ ready: true, database, origin, appUser, sourceUser, sourcePassword, epoch, bindings,
      requester: Number(requester), reviewer: Number(reviewer), userToken: signUserToken(Number(requester), { secret }) })
    const input = readline.createInterface({ input: process.stdin })
    let sequence = Promise.resolve()
    input.on('line', (line) => {
      sequence = sequence.then(async () => {
        const command = JSON.parse(line)
        if (command.name === 'newCard') {
          const cardKey = `joint-method-${crypto.randomUUID()}`
          const [cardId] = await owner.query(`INSERT INTO method_cards(card_key,title,family,problem_kinds,when_to_use,steps,embedding,embed_model)
            VALUES(:cardKey,'合成受控方法卡🔒','sre','["decision"]','只验证机械安全边界','["核对版本","独立审批","核验回执"]',:embedding,'synthetic-joint')`,
          { replacements: { cardKey, embedding: Buffer.from('synthetic-joint-vector') } })
          await owner.query("INSERT INTO method_card_protection(card_key,namespace,executor_db_user) VALUES(:cardKey,'fdesage-ops',:sourceUser)", { replacements: { cardKey, sourceUser } })
          output({ cardId: Number(cardId) })
        } else if (command.name === 'state') {
          output({ card: await one('SELECT id,review_status,revision,verification_intent_id FROM method_cards WHERE id=:id', { id: command.cardId }),
            operations: await one('SELECT COUNT(*) AS n FROM method_card_source_operations WHERE card_id=:id', { id: command.cardId }),
            audits: await one('SELECT COUNT(*) AS n FROM method_card_source_audit WHERE card_id=:id', { id: command.cardId }) })
        } else if (command.name === 'stop') {
          const apiChildExit = await new Promise((resolve) => { child.once('exit', resolve); child.send({ stop: true }) })
          await owner.close(); await administrator.close(); output({ stopped: true, apiChildExit }); process.exit(0)
        } else throw new Error('Unknown fixture command')
      }).catch(() => { output({ fixtureError: true }); process.exitCode = 1 })
    })
  }
  start().catch(async () => { if (child) child.kill(); if (owner) await owner.close(); await administrator.close(); output({ fixtureError: true }); process.exit(1) })
}
