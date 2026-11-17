import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const runtimePath = process.env.AI_NATIVE_LLAMA_RUNTIME_DIR;
const modelFile = process.env.AI_NATIVE_GGUF_MODEL_PATH;
if (!runtimePath || !modelFile) {
  throw new Error('Set AI_NATIVE_LLAMA_RUNTIME_DIR and AI_NATIVE_GGUF_MODEL_PATH to existing local paths');
}
const runtimeDir = resolve(runtimePath);
const modelPath = resolve(modelFile);
const modelName = basename(modelPath, '.gguf');
const port = Number(process.env.AI_NATIVE_LOCAL_MODEL_PORT || 8798);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('AI_NATIVE_LOCAL_MODEL_PORT must be between 1 and 65535');
}

const { getLlama, LlamaChatSession } = await import(pathToFileURL(join(runtimeDir, 'node_modules', 'node-llama-cpp', 'dist', 'index.js')).href);
const llama = await getLlama({ build: 'never', skipDownload: true, logLevel: 'error' });
const model = await llama.loadModel({ modelPath });
const contextSize = 4096;
const context = await model.createContext({ contextSize });
let busy = false;

function respond(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(payload));
}

function reject(res, status, message) {
  respond(res, status, { error: { message } });
}

const server = createServer({ requestTimeout: 20_000 }, async (req, res) => {
  if (!/^(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(req.headers.host ?? '')) return reject(res, 403, 'Loopback requests only');
  if (req.method === 'GET' && req.url === '/health') return respond(res, 200, { ok: true, model: modelName });
  if (req.method !== 'POST' || req.url !== '/v1/chat/completions') return reject(res, 404, 'Unknown endpoint');
  if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') return reject(res, 415, 'JSON request required');
  if (busy) return reject(res, 429, 'Another local model request is in progress');

  busy = true;
  const disconnect = new AbortController();
  res.once('close', () => { if (!res.writableEnded) disconnect.abort(); });
  try {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req.iterator({ destroyOnReturn: false })) {
      bytes += chunk.length;
      if (bytes > 32 * 1024) {
        req.resume();
        return reject(res, 413, 'Request body exceeds 32 KiB');
      }
      chunks.push(chunk);
    }

    let systemPrompt, userContent, input;
    try {
      const { messages } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (messages?.length !== 2 || messages[0]?.role !== 'system' || messages[1]?.role !== 'user' ||
          messages.some(({ content }) => typeof content !== 'string')) throw new Error('Invalid messages');
      systemPrompt = messages[0].content;
      userContent = messages[1].content;
      input = JSON.parse(userContent);
      if (!Array.isArray(input.allowed_actions) || !Array.isArray(input.knowledge) ||
          !input.allowed_actions.every(item => typeof item?.name === 'string' && item.name) ||
          !input.knowledge.every(item => typeof item?.id === 'string' && item.id)) throw new Error('Invalid input');
    } catch {
      return reject(res, 400, 'Expected system/user messages with allowed_actions and knowledge lists in user JSON');
    }

    const maxTokens = 256;
    if (model.tokenize(systemPrompt + userContent).length > contextSize - maxTokens - 128) {
      return reject(res, 413, 'Input exceeds local model context budget');
    }
    const evidenceIds = [...new Set(input.knowledge.map(item => item.id))];
    const allowedActions = [...new Set(input.allowed_actions.map(item => item.name))];
    const grammar = await llama.createGrammarForJsonSchema({
      type: 'object',
      properties: {
        action: { enum: [null, ...allowedActions] },
        rationale: { type: 'string', minLength: 1, maxLength: 600 },
        evidence_ids: {
          type: 'array',
          items: evidenceIds.length ? { enum: evidenceIds } : { type: 'string' },
          maxItems: Math.min(10, evidenceIds.length),
        },
      },
      required: ['action', 'rationale', 'evidence_ids'],
      additionalProperties: false,
    });

    const sequence = context.getSequence();
    const initial = sequence.tokenMeter.getState();
    const session = new LlamaChatSession({ contextSequence: sequence, systemPrompt, autoDisposeSequence: true });
    try {
      const content = await session.prompt(userContent, {
        grammar, temperature: 0, maxTokens,
        signal: AbortSignal.any([disconnect.signal, AbortSignal.timeout(12_000)]),
      });
      JSON.parse(content);
      const promptTokens = sequence.tokenMeter.usedInputTokens - initial.usedInputTokens;
      const completionTokens = sequence.tokenMeter.usedOutputTokens - initial.usedOutputTokens;
      respond(res, 200, {
        id: randomUUID(), model: modelName, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content } }],
        usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens },
      });
    } finally {
      session.dispose();
    }
  } catch (error) {
    if (!res.destroyed) {
      if (error.name === 'TimeoutError') return reject(res, 504, 'Local inference timed out');
      reject(res, 502, 'Local inference did not produce a complete proposal');
    }
  } finally {
    busy = false;
  }
});

server.listen(port, '127.0.0.1', () => console.log(`Local model ready at http://127.0.0.1:${port}/v1 (${modelName})`));
