import PostalMime from 'postal-mime';
import jwtUtils from './utils/jwt-utils';
import emailUtils from './utils/email-utils';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };
const RECEIVE_STATUS = 0;
const NOONE_STATUS = 7;
const NORMAL = 0;

function json(data, status = 200) {
	return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function ok(data = {}, message = 'success') {
	return json({ code: 200, message, data });
}

function fail(status, message) {
	return json({ code: status, message, data: null }, status);
}

function isTruthy(value) {
	return value === true || value === 'true' || value === '1' || value === 1;
}

function normalizeEmail(value) {
	return String(value || '').trim().toLowerCase();
}

function parseDomains(value) {
	if (Array.isArray(value)) {
		return value.map(item => String(item || '').trim().toLowerCase()).filter(Boolean);
	}
	if (typeof value === 'string') {
		try {
			const parsed = JSON.parse(value);
			if (Array.isArray(parsed)) {
				return parsed.map(item => String(item || '').trim().toLowerCase()).filter(Boolean);
			}
		} catch (error) {
			return value.split(',').map(item => item.trim().toLowerCase()).filter(Boolean);
		}
	}
	return [];
}

function getRecipientDomain(email) {
	return normalizeEmail(email).split('@')[1] || '';
}

async function ensureSchema(env) {
	await env.db.exec(`
		CREATE TABLE IF NOT EXISTS email (
			email_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
			send_email TEXT,
			name TEXT,
			account_id INTEGER NOT NULL DEFAULT 0,
			user_id INTEGER NOT NULL DEFAULT 0,
			subject TEXT,
			text TEXT,
			content TEXT,
			cc TEXT DEFAULT '[]',
			bcc TEXT DEFAULT '[]',
			recipient TEXT,
			to_email TEXT DEFAULT '' NOT NULL,
			to_name TEXT DEFAULT '' NOT NULL,
			in_reply_to TEXT DEFAULT '',
			relation TEXT DEFAULT '',
			message_id TEXT DEFAULT '',
			type INTEGER DEFAULT 0 NOT NULL,
			status INTEGER DEFAULT 0 NOT NULL,
			resend_email_id TEXT,
			message TEXT,
			unread INTEGER DEFAULT 0 NOT NULL,
			create_time DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
			is_del INTEGER DEFAULT 0 NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_email_to_email_time
			ON email(to_email, create_time DESC);
	`);
}

async function verifyPublicToken(request, env) {
	const token = request.headers.get('Authorization') || '';
	if (!token) {
		return null;
	}
	const payload = await jwtUtils.verifyToken({ env }, token);
	if (!payload || payload.type !== 'public' || payload.admin !== normalizeEmail(env.admin)) {
		return null;
	}
	return payload;
}

async function handleGenToken(request, env) {
	const body = await request.json().catch(() => ({}));
	const email = normalizeEmail(body.email);
	const password = String(body.password || '');
	const adminEmail = normalizeEmail(env.admin);
	const adminPassword = String(env.admin_password || '');

	if (!adminEmail || !adminPassword || !env.jwt_secret) {
		return fail(500, 'worker variables not configured');
	}

	if (email !== adminEmail) {
		return ok({}, '输入的邮箱不存在');
	}

	if (password !== adminPassword) {
		return ok({}, '密码错误');
	}

	const token = await jwtUtils.generateToken(
		{ env },
		{ type: 'public', admin: adminEmail },
		60 * 60
	);

	return ok({ token });
}

async function handleEmailList(request, env) {
	const tokenPayload = await verifyPublicToken(request, env);
	if (!tokenPayload) {
		return fail(401, 'token验证失败');
	}

	const body = await request.json().catch(() => ({}));
	const toEmail = normalizeEmail(body.toEmail);
	const timeSort = String(body.timeSort || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
	const size = Math.max(1, Math.min(100, Number(body.size || 20)));
	const num = Math.max(1, Number(body.num || 1));
	const offset = (num - 1) * size;

	if (!toEmail) {
		return fail(400, 'toEmail不能为空');
	}

	await ensureSchema(env);

	const stmt = env.db.prepare(`
		SELECT
			email_id AS emailId,
			send_email AS sendEmail,
			name AS sendName,
			subject,
			to_email AS toEmail,
			to_name AS toName,
			type,
			create_time AS createTime,
			content,
			text,
			is_del AS isDel
		FROM email
		WHERE lower(to_email) = ?
		ORDER BY create_time ${timeSort}
		LIMIT ? OFFSET ?
	`).bind(toEmail, size, offset);

	const result = await stmt.all();
	return ok(result.results || []);
}

async function handleRoot() {
	return new Response('cloud-mail codex mode', { status: 200 });
}

async function handleFetch(request, env, ctx) {
	const url = new URL(request.url);

	if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/healthz')) {
		return handleRoot();
	}

	if (request.method === 'POST' && url.pathname === '/api/public/genToken') {
		return handleGenToken(request, env);
	}

	if (request.method === 'POST' && url.pathname === '/api/public/emailList') {
		return handleEmailList(request, env);
	}

	if (request.method === 'POST' && url.pathname === '/public/genToken') {
		return handleGenToken(request, env);
	}

	if (request.method === 'POST' && url.pathname === '/public/emailList') {
		return handleEmailList(request, env);
	}

	return fail(404, 'not found');
}

async function handleInbound(message, env) {
	await ensureSchema(env);

	const recipient = normalizeEmail(message.to);
	const domains = parseDomains(env.domain);
	const catchAllEnabled = isTruthy(env.codex_console_catch_all);

	if (!recipient) {
		message.setReject('Recipient not found');
		return;
	}

	if (!domains.includes(getRecipientDomain(recipient))) {
		message.setReject('Recipient not found');
		return;
	}

	if (!catchAllEnabled) {
		message.setReject('Recipient not found');
		return;
	}

	const rawMime = await new Response(message.raw).text();
	const parsed = await PostalMime.parse(rawMime);
	const fromAddress = normalizeEmail(parsed?.from?.address || '');
	const fromName = String(parsed?.from?.name || emailUtils.getName(fromAddress) || '');
	const recipientList = Array.isArray(parsed?.to) ? parsed.to : [{ address: recipient, name: emailUtils.getName(recipient) }];
	const toName = recipientList.find(item => normalizeEmail(item.address) === recipient)?.name || emailUtils.getName(recipient);

	await env.db.prepare(`
		INSERT INTO email (
			send_email, name, account_id, user_id, subject, text, content,
			cc, bcc, recipient, to_email, to_name, in_reply_to, relation,
			message_id, type, status, unread, is_del
		) VALUES (?, ?, 0, 0, ?, ?, ?, '[]', '[]', ?, ?, ?, ?, ?, ?, 0, ?, 0, ?)
	`).bind(
		fromAddress,
		fromName,
		String(parsed?.subject || ''),
		String(parsed?.text || ''),
		String(parsed?.html || parsed?.text || ''),
		JSON.stringify(recipientList),
		recipient,
		String(toName || ''),
		String(parsed?.inReplyTo || ''),
		JSON.stringify(parsed?.references || []),
		String(parsed?.messageId || ''),
		NOONE_STATUS,
		NORMAL
	).run();
}

export default {
	async fetch(request, env, ctx) {
		return handleFetch(request, env, ctx);
	},

	async email(message, env, ctx) {
		await handleInbound(message, env);
	}
};
