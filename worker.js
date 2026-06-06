/* ============================================================
   Condscript API — Cloudflare Worker
   Routes:
     POST  /auth/send-otp
     POST  /auth/verify-otp
     POST  /auth/logout
     GET   /auth/me

     GET   /ward
     POST  /ward/create
     POST  /ward/members/add
     POST  /ward/members/remove
     POST  /ward/leave

     GET   /meetings?limit=N
     POST  /meetings
     GET   /meetings/:date                       — legacy: most recent meeting on date
     GET   /meetings/id/:id
     PATCH /meetings/id/:id/metadata             — write fixed fields to meetings table
     POST  /meetings/id/:id/components/batch     — upsert ordered components
     POST  /meetings/id/:id/components/replace-type
     DELETE /meetings/id/:id
     GET   /meetings/export.csv
============================================================ */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }
function randomCode() { return String(Math.floor(100000 + Math.random() * 900000)); }

// ── JWT ────────────────────────────────────────────────────────
async function signJwt(payload, secret) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' })).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const body   = btoa(JSON.stringify(payload)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const signing = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signing));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${signing}.${b64}`;
}
async function verifyJwt(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const signing = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(signing));
    if (!valid) return null;
    return JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
  } catch { return null; }
}

// ── Database ───────────────────────────────────────────────────
async function query(env, sql, params = []) {
  const connStr = env.DATABASE_URL;
  let host;
  try { host = new URL(connStr).host; }
  catch { throw new Error('Invalid DATABASE_URL'); }
  if (!host) throw new Error('Invalid DATABASE_URL');

  const res = await fetch(`https://${host}/sql`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Neon-Connection-String': connStr,
      'Neon-Pool-Opt-In': 'true',
    },
    body: JSON.stringify({ query: sql, params }),
  });
  if (!res.ok) { const t = await res.text(); throw new Error(`DB ${res.status}: ${t}`); }
  return res.json();
}

// ── Session helpers ────────────────────────────────────────────
async function getSession(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  const payload = await verifyJwt(token, env.JWT_SECRET);
  if (!payload?.session_id) return null;
  const r = await query(env,
    `SELECT s.id, s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1 AND s.expires_at > NOW()`,
    [payload.session_id]);
  return r.rows?.[0] || null;
}
async function getUserWard(env, userId) {
  const r = await query(env,
    `SELECT w.id, w.name FROM wards w JOIN ward_members wm ON wm.ward_id = w.id WHERE wm.user_id = $1 LIMIT 1`,
    [userId]);
  return r.rows?.[0] || null;
}

// ── Email ──────────────────────────────────────────────────────
async function sendOtpEmail(env, email, code) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.RESEND_FROM,
      to: email,
      subject: 'Your Condscript login code',
      html: `<div style="font-family:sans-serif;max-width:400px;margin:40px auto">
        <h2 style="color:#1a3a6b">Condscript Login</h2>
        <p>Your one-time login code is:</p>
        <div style="font-size:2.5rem;font-weight:bold;letter-spacing:.3em;color:#1a3a6b;margin:20px 0">${code}</div>
        <p style="color:#666;font-size:.9rem">Expires in 10 minutes.</p></div>`,
    }),
  });
  if (!res.ok) {
    const t = await res.text();
    let message = t;
    try { message = JSON.parse(t).message || t; } catch {}
    if (res.status === 403 && message.includes('testing emails')) {
      throw new Error('Email sending is still in Resend test mode. Verify a sending domain in Resend and set RESEND_FROM to an address on that domain before logging in with other email addresses.');
    }
    throw new Error(`Email error: ${message}`);
  }
}

// ── Auth handlers ──────────────────────────────────────────────
async function handleSendOtp(request, env) {
  const { email } = await request.json();
  if (!email?.includes('@')) return err('Valid email required');
  const code = randomCode();
  await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);
  await query(env, `INSERT INTO otp_codes (email, code, expires_at) VALUES ($1, $2, $3)`,
    [email, code, new Date(Date.now() + 10*60*1000).toISOString()]);
  try {
    await sendOtpEmail(env, email, code);
  } catch (e) {
    await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);
    throw e;
  }
  return json({ ok: true });
}

async function handleVerifyOtp(request, env) {
  const { email, code } = await request.json();
  if (!email || !code) return err('Email and code required');
  const r = await query(env, `SELECT id FROM otp_codes WHERE email = $1 AND code = $2 AND expires_at > NOW()`, [email, code]);
  if (!r.rows?.length) return err('Invalid or expired code', 401);
  await query(env, `DELETE FROM otp_codes WHERE email = $1`, [email]);
  await query(env, `INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING`, [email]);
  const ur = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  const userId = ur.rows[0].id;
  const expires = new Date(Date.now() + 30*24*60*60*1000).toISOString();
  const sr = await query(env, `INSERT INTO sessions (user_id, expires_at) VALUES ($1, $2) RETURNING id`, [userId, expires]);
  const token = await signJwt({ session_id: sr.rows[0].id }, env.JWT_SECRET);
  const ward = await getUserWard(env, userId);
  return json({ token, email, ward });
}

async function handleLogout(request, env) {
  const session = await getSession(request, env);
  if (session) {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.replace('Bearer ','').trim();
    const payload = await verifyJwt(token, env.JWT_SECRET);
    if (payload?.session_id) await query(env, `DELETE FROM sessions WHERE id = $1`, [payload.session_id]);
  }
  return json({ ok: true });
}

async function handleMe(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  return json({ email: session.email, ward });
}

// ── Ward handlers ──────────────────────────────────────────────
async function handleGetWard(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return json({ ward: null });
  const members = await query(env,
    `SELECT u.email, wm.added_at FROM ward_members wm JOIN users u ON u.id = wm.user_id WHERE wm.ward_id = $1 ORDER BY wm.added_at`,
    [ward.id]);
  return json({ ward: { ...ward, members: members.rows } });
}

async function handleCreateWard(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  if (await getUserWard(env, session.user_id)) return err('You are already in a ward. Leave it first.');
  const { name } = await request.json();
  if (!name?.trim()) return err('Ward name required');
  const wr = await query(env, `INSERT INTO wards (name, created_by) VALUES ($1, $2) RETURNING id`, [name.trim(), session.user_id]);
  const wardId = wr.rows[0].id;
  await query(env, `INSERT INTO ward_members (ward_id, user_id, added_by) VALUES ($1, $2, $2)`, [wardId, session.user_id]);
  return json({ ward: { id: wardId, name: name.trim() } });
}

async function handleAddMember(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('You are not in a ward');
  const { email } = await request.json();
  if (!email?.includes('@')) return err('Valid email required');
  const tu = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  if (tu.rows?.length) {
    const tw = await getUserWard(env, tu.rows[0].id);
    if (tw) {
      if (tw.id === ward.id) return err('That person is already in your ward');
      return err(`${email} is already in another ward. They must leave it first.`);
    }
  }
  await query(env, `INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING`, [email]);
  const ur = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  await query(env, `INSERT INTO ward_members (ward_id, user_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [ward.id, ur.rows[0].id, session.user_id]);
  return json({ ok: true });
}

async function handleRemoveMember(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('You are not in a ward');
  const { email } = await request.json();
  const tu = await query(env, `SELECT id FROM users WHERE email = $1`, [email]);
  if (!tu.rows?.length) return err('User not found');
  if (tu.rows[0].id === session.user_id) return err('Use Leave Ward to remove yourself');
  await query(env, `DELETE FROM ward_members WHERE ward_id = $1 AND user_id = $2`, [ward.id, tu.rows[0].id]);
  return json({ ok: true });
}

async function handleLeaveWard(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('You are not in a ward');
  await query(env, `DELETE FROM ward_members WHERE ward_id = $1 AND user_id = $2`, [ward.id, session.user_id]);
  return json({ ok: true });
}

// ── Meeting helpers ────────────────────────────────────────────
async function createMeeting(env, wardId, userId, meta = {}, wardName = '') {
  if (!meta.meeting_date) throw new Error('meeting_date is required');
  const meetingWardName = wardName || meta.ward_name || '';
  const r = await query(env,
    `INSERT INTO meetings (ward_id, meeting_date, meeting_time, location, ward_name, created_by)
     VALUES ($1, $2, NULLIF($3, '')::time, NULLIF($4, ''), NULLIF($5, ''), $6)
     RETURNING id`,
    [wardId, meta.meeting_date, meta.meeting_time || '', meta.location || '', meetingWardName, userId]);
  return r.rows[0].id;
}

async function ensureMeeting(env, wardId, date, userId, wardName = '') {
  const r = await query(env,
    `SELECT id FROM meetings
     WHERE ward_id = $1 AND meeting_date = $2
     ORDER BY created_at DESC, id DESC
     LIMIT 1`,
    [wardId, date]);
  if (r.rows?.length) return r.rows[0].id;
  return await createMeeting(env, wardId, userId, { meeting_date: date }, wardName);
}

async function getMeetingIdForWard(env, wardId, meetingId) {
  const r = await query(env, `SELECT id FROM meetings WHERE ward_id = $1 AND id = $2`, [wardId, meetingId]);
  return r.rows?.[0]?.id || null;
}

async function upsertComponent(env, meetingId, userId, comp) {
  await query(env,
    `INSERT INTO meeting_components
       (meeting_id, component_type, component_order,
        person_name, person_title, topic, hymn_number, hymn_title, notes, extra_data, updated_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     ON CONFLICT (meeting_id, component_type, component_order) DO UPDATE SET
       person_name  = EXCLUDED.person_name,
       person_title = EXCLUDED.person_title,
       topic        = EXCLUDED.topic,
       hymn_number  = EXCLUDED.hymn_number,
       hymn_title   = EXCLUDED.hymn_title,
       notes        = EXCLUDED.notes,
       extra_data   = EXCLUDED.extra_data,
       updated_by   = EXCLUDED.updated_by,
       updated_at   = NOW()`,
    [
      meetingId,
      comp.component_type, comp.component_order ?? 0,
      comp.person_name  ?? null, comp.person_title ?? null,
      comp.topic        ?? null, comp.hymn_number  ?? null,
      comp.hymn_title   ?? null, comp.notes        ?? null,
      comp.extra_data   ? JSON.stringify(comp.extra_data) : null,
      userId,
    ]
  );
}

// ── Meeting handlers ───────────────────────────────────────────
async function handleListMeetings(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '52'), 200);
  const r = await query(env,
    `SELECT m.id, m.meeting_date, m.meeting_time, m.location, m.ward_name,
            m.presiding_name, m.conducting_name, u.email as created_by, m.created_at
     FROM meetings m LEFT JOIN users u ON u.id = m.created_by
     WHERE m.ward_id = $1 ORDER BY m.meeting_date DESC, m.meeting_time NULLS LAST, m.created_at DESC LIMIT $2`,
    [ward.id, limit]);
  return json({ meetings: r.rows || [] });
}

async function handleHistory(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);

  const url = new URL(request.url);
  const q = (url.searchParams.get('q') || '').trim().toLowerCase();
  const search = q ? `%${q}%` : null;

  const speakerParams = search ? [ward.id, search] : [ward.id];
  const speakerSearch = search ? `AND lower(mc.person_name) LIKE $2` : '';
  const speakerRows = await query(env,
    `SELECT m.id as meeting_id, m.meeting_date, m.meeting_time, m.location,
            mc.person_name, mc.topic, mc.component_order
     FROM meeting_components mc
     JOIN meetings m ON m.id = mc.meeting_id
     WHERE m.ward_id = $1
       AND mc.component_type = 'talk'
       AND NULLIF(trim(mc.person_name), '') IS NOT NULL
       ${speakerSearch}
     ORDER BY m.meeting_date DESC, m.meeting_time DESC NULLS LAST, mc.component_order ASC
     LIMIT 500`,
    speakerParams);

  const prayerParams = search ? [ward.id, search] : [ward.id];
  const prayerSearch = search ? `WHERE lower(name) LIKE $2` : '';
  const prayerRows = await query(env,
    `SELECT meeting_id, meeting_date, meeting_time, location, prayer_type, name
     FROM (
       SELECT id as meeting_id, meeting_date, meeting_time, location, 'Invocation' as prayer_type, invocation as name, 1 as prayer_order
       FROM meetings
       WHERE ward_id = $1 AND NULLIF(trim(invocation), '') IS NOT NULL
       UNION ALL
       SELECT id as meeting_id, meeting_date, meeting_time, location, 'Benediction' as prayer_type, benediction as name, 2 as prayer_order
       FROM meetings
       WHERE ward_id = $1 AND NULLIF(trim(benediction), '') IS NOT NULL
     ) prayers
     ${prayerSearch}
     ORDER BY meeting_date DESC, meeting_time DESC NULLS LAST, prayer_order ASC
     LIMIT 500`,
    prayerParams);

  return json({ speakers: speakerRows.rows || [], prayers: prayerRows.rows || [] });
}

async function getMeetingPayloadById(env, wardId, meetingId) {
  const mr = await query(env,
    `SELECT id, meeting_date, meeting_time, location,
            ward_name, presiding_name, conducting_name, chorister, organist,
            invocation, benediction, is_fast_sunday,
            opening_hymn_number, opening_hymn_title,
            sacrament_hymn_number, sacrament_hymn_title,
            closing_hymn_number, closing_hymn_title
     FROM meetings WHERE ward_id = $1 AND id = $2`,
    [wardId, meetingId]);
  if (!mr.rows?.length) return null;

  const { id, meeting_date, ...metadata } = mr.rows[0];
  const cr = await query(env,
    `SELECT mc.component_type, mc.component_order, mc.person_name, mc.person_title,
            mc.topic, mc.hymn_number, mc.hymn_title, mc.notes, mc.extra_data,
            u.email as updated_by_email, mc.updated_at
     FROM meeting_components mc LEFT JOIN users u ON u.id = mc.updated_by
     WHERE mc.meeting_id = $1 ORDER BY mc.component_order, mc.component_type`,
    [id]);
  return { id, date: meeting_date, metadata, components: cr.rows || [] };
}

async function getMeetingPayloadByDate(env, wardId, date) {
  const r = await query(env,
    `SELECT id FROM meetings
     WHERE ward_id = $1 AND meeting_date = $2
     ORDER BY created_at DESC, id DESC
     LIMIT 1`,
    [wardId, date]);
  if (!r.rows?.length) return null;
  return await getMeetingPayloadById(env, wardId, r.rows[0].id);
}

async function handleGetMeeting(request, env, date) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  return json({ meeting: await getMeetingPayloadByDate(env, ward.id, date) });
}

async function handleCreateMeeting(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);

  const meta = await request.json();
  if (!meta.meeting_date) return err('meeting_date is required');
  const meetingId = await createMeeting(env, ward.id, session.user_id, meta, ward.name);
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, meetingId) }, 201);
}

async function handleGetMeetingById(request, env, meetingId) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  return json({ meeting: await getMeetingPayloadById(env, ward.id, meetingId) });
}

async function handleDeleteMeeting(request, env, meetingId) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const id = await getMeetingIdForWard(env, ward.id, meetingId);
  if (!id) return err('Meeting not found', 404);
  await query(env, `DELETE FROM meeting_components WHERE meeting_id = $1`, [id]);
  await query(env, `DELETE FROM meetings WHERE ward_id = $1 AND id = $2`, [ward.id, id]);
  return json({ ok: true });
}

async function handleUpsertMetadataById(request, env, meetingId) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);

  const id = await getMeetingIdForWard(env, ward.id, meetingId);
  if (!id) return err('Meeting not found', 404);
  const meta = await request.json();

  const allowed = ['ward_name','presiding_name','conducting_name','chorister','organist',
    'invocation','benediction','is_fast_sunday','meeting_date','meeting_time','location',
    'opening_hymn_number','opening_hymn_title',
    'sacrament_hymn_number','sacrament_hymn_title',
    'closing_hymn_number','closing_hymn_title'];

  const sets = []; const vals = []; let i = 1;
  allowed.forEach(f => {
    if (meta[f] !== undefined) {
      const valueExpr = f === 'meeting_time' ? `NULLIF($${i}, '')::time` : `$${i}`;
      sets.push(`${f} = ${valueExpr}`);
      vals.push(f === 'ward_name' ? ward.name : meta[f]);
      i++;
    }
  });
  if (!sets.length) return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, id) });

  vals.push(id);
  await query(env, `UPDATE meetings SET ${sets.join(', ')} WHERE id = $${i}`, vals);
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, id) });
}

async function handleUpsertMetadata(request, env, date) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const meetingId = await ensureMeeting(env, ward.id, date, session.user_id, ward.name);
  return await handleUpsertMetadataById(request, env, meetingId);
}

async function handleBatchComponents(request, env, date) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const { components } = await request.json();
  if (!Array.isArray(components)) return err('components must be an array');
  const meetingId = await ensureMeeting(env, ward.id, date, session.user_id, ward.name);
  for (const comp of components) {
    if (!comp.component_type) continue;
    await upsertComponent(env, meetingId, session.user_id, comp);
  }
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, meetingId) });
}

async function handleBatchComponentsById(request, env, meetingId) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const id = await getMeetingIdForWard(env, ward.id, meetingId);
  if (!id) return err('Meeting not found', 404);
  const { components } = await request.json();
  if (!Array.isArray(components)) return err('components must be an array');
  for (const comp of components) {
    if (!comp.component_type) continue;
    await upsertComponent(env, id, session.user_id, comp);
  }
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, id) });
}

function normalizeComponentForDb(comp, fallbackOrder = 0) {
  return {
    component_type: comp.component_type,
    component_order: comp.component_order ?? fallbackOrder,
    person_name: comp.person_name ?? null,
    person_title: comp.person_title ?? null,
    topic: comp.topic ?? null,
    hymn_number: comp.hymn_number ?? null,
    hymn_title: comp.hymn_title ?? null,
    notes: comp.notes ?? null,
    extra_data: comp.extra_data ? JSON.stringify(comp.extra_data) : null,
  };
}

async function replaceComponentsAtomic(env, meetingId, userId, componentTypes, components) {
  if (!componentTypes?.length) {
    for (const comp of (components || [])) {
      if (!comp.component_type) continue;
      await upsertComponent(env, meetingId, userId, comp);
    }
    return;
  }

  const validComponents = (components || []).filter(c => c.component_type).map(normalizeComponentForDb);
  const params = [meetingId, ...componentTypes];
  const typePlaceholders = componentTypes.map((_, i) => `$${i + 2}`).join(',');

  if (!validComponents.length) {
    await query(env,
      `DELETE FROM meeting_components WHERE meeting_id = $1 AND component_type IN (${typePlaceholders})`,
      params);
    return;
  }

  const rowsSql = [];
  let p = params.length + 1;
  for (const comp of validComponents) {
    rowsSql.push(`($1,$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
    params.push(
      comp.component_type,
      comp.component_order,
      comp.person_name,
      comp.person_title,
      comp.topic,
      comp.hymn_number,
      comp.hymn_title,
      comp.notes,
      comp.extra_data,
      userId,
    );
  }

  await query(env,
    `WITH deleted AS (
       DELETE FROM meeting_components
       WHERE meeting_id = $1 AND component_type IN (${typePlaceholders})
     )
     INSERT INTO meeting_components
       (meeting_id, component_type, component_order,
        person_name, person_title, topic, hymn_number, hymn_title, notes, extra_data, updated_by)
     VALUES ${rowsSql.join(',')}
     ON CONFLICT (meeting_id, component_type, component_order) DO UPDATE SET
       person_name  = EXCLUDED.person_name,
       person_title = EXCLUDED.person_title,
       topic        = EXCLUDED.topic,
       hymn_number  = EXCLUDED.hymn_number,
       hymn_title   = EXCLUDED.hymn_title,
       notes        = EXCLUDED.notes,
       extra_data   = EXCLUDED.extra_data,
       updated_by   = EXCLUDED.updated_by,
       updated_at   = NOW()`,
    params);
}

async function handleReplaceType(request, env, date) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const { component_types, components } = await request.json();
  const meetingId = await ensureMeeting(env, ward.id, date, session.user_id, ward.name);
  await replaceComponentsAtomic(env, meetingId, session.user_id, component_types || [], components || []);
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, meetingId) });
}

async function handleReplaceTypeById(request, env, meetingId) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const id = await getMeetingIdForWard(env, ward.id, meetingId);
  if (!id) return err('Meeting not found', 404);
  const { component_types, components } = await request.json();
  await replaceComponentsAtomic(env, id, session.user_id, component_types || [], components || []);
  return json({ ok: true, meeting: await getMeetingPayloadById(env, ward.id, id) });
}

async function handleExportCsv(request, env) {
  const session = await getSession(request, env);
  if (!session) return err('Unauthorized', 401);
  const ward = await getUserWard(env, session.user_id);
  if (!ward) return err('Not in a ward', 403);
  const r = await query(env,
    `SELECT m.meeting_date, m.meeting_time, m.location,
            m.ward_name, m.presiding_name, m.conducting_name,
            m.chorister, m.organist, m.invocation, m.benediction, m.is_fast_sunday,
            m.opening_hymn_number, m.opening_hymn_title,
            m.sacrament_hymn_number, m.sacrament_hymn_title,
            m.closing_hymn_number, m.closing_hymn_title,
            mc.component_type, mc.component_order,
            mc.person_name, mc.person_title, mc.topic,
            mc.hymn_number, mc.hymn_title, mc.notes,
            u.email as updated_by, mc.updated_at
     FROM meetings m
     LEFT JOIN meeting_components mc ON mc.meeting_id = m.id
     LEFT JOIN users u ON u.id = mc.updated_by
     WHERE m.ward_id = $1
     ORDER BY m.meeting_date DESC, m.meeting_time NULLS LAST, mc.component_order, mc.component_type`,
    [ward.id]);
  const rows = r.rows || [];
  const headers = ['meeting_date','meeting_time','location','ward_name','presiding_name','conducting_name','chorister','organist',
    'invocation','benediction','is_fast_sunday',
    'opening_hymn_number','opening_hymn_title','sacrament_hymn_number','sacrament_hymn_title','closing_hymn_number','closing_hymn_title',
    'component_type','component_order','person_name','person_title','topic','hymn_number','hymn_title','notes','updated_by','updated_at'];
  function csvCell(value) {
    let v = String(value ?? '');
    if (/^[=+\-@]/.test(v)) v = `'${v}`;
    if (v.includes(',') || v.includes('"') || v.includes('\n')) return `"${v.replace(/"/g,'""')}"`;
    return v;
  }
  const csvLines = [headers.map(csvCell).join(',')];
  for (const row of rows) {
    csvLines.push(headers.map(h => csvCell(row[h])).join(','));
  }
  return new Response(csvLines.join('\n'), {
    headers: { ...CORS_HEADERS, 'Content-Type':'text/csv', 'Content-Disposition':`attachment; filename="condscript-${ward.name}.csv"` },
  });
}

// ── Router ─────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    try {
      if (path === '/auth/send-otp'   && method === 'POST') return await handleSendOtp(request, env);
      if (path === '/auth/verify-otp' && method === 'POST') return await handleVerifyOtp(request, env);
      if (path === '/auth/logout'     && method === 'POST') return await handleLogout(request, env);
      if (path === '/auth/me'         && method === 'GET')  return await handleMe(request, env);

      if (path === '/ward'                && method === 'GET')  return await handleGetWard(request, env);
      if (path === '/ward/create'         && method === 'POST') return await handleCreateWard(request, env);
      if (path === '/ward/members/add'    && method === 'POST') return await handleAddMember(request, env);
      if (path === '/ward/members/remove' && method === 'POST') return await handleRemoveMember(request, env);
      if (path === '/ward/leave'          && method === 'POST') return await handleLeaveWard(request, env);

      if (path === '/history'              && method === 'GET')  return await handleHistory(request, env);

      if (path === '/meetings'             && method === 'GET')  return await handleListMeetings(request, env);
      if (path === '/meetings'             && method === 'POST') return await handleCreateMeeting(request, env);
      if (path === '/meetings/export.csv'  && method === 'GET')  return await handleExportCsv(request, env);

      const idMatch = path.match(/^\/meetings\/id\/([0-9a-fA-F-]{36})$/);
      if (idMatch && method === 'GET')    return await handleGetMeetingById(request, env, idMatch[1]);
      if (idMatch && method === 'DELETE') return await handleDeleteMeeting(request, env, idMatch[1]);

      const idMetaMatch = path.match(/^\/meetings\/id\/([0-9a-fA-F-]{36})\/metadata$/);
      if (idMetaMatch && method === 'PATCH') return await handleUpsertMetadataById(request, env, idMetaMatch[1]);

      const idBatchMatch = path.match(/^\/meetings\/id\/([0-9a-fA-F-]{36})\/components\/batch$/);
      if (idBatchMatch && method === 'POST') return await handleBatchComponentsById(request, env, idBatchMatch[1]);

      const idReplaceMatch = path.match(/^\/meetings\/id\/([0-9a-fA-F-]{36})\/components\/replace-type$/);
      if (idReplaceMatch && method === 'POST') return await handleReplaceTypeById(request, env, idReplaceMatch[1]);

      const dateMatch = path.match(/^\/meetings\/(\d{4}-\d{2}-\d{2})$/);
      if (dateMatch && method === 'GET')   return await handleGetMeeting(request, env, dateMatch[1]);

      const metaMatch = path.match(/^\/meetings\/(\d{4}-\d{2}-\d{2})\/metadata$/);
      if (metaMatch && method === 'PATCH') return await handleUpsertMetadata(request, env, metaMatch[1]);

      const batchMatch = path.match(/^\/meetings\/(\d{4}-\d{2}-\d{2})\/components\/batch$/);
      if (batchMatch && method === 'POST') return await handleBatchComponents(request, env, batchMatch[1]);

      const replaceMatch = path.match(/^\/meetings\/(\d{4}-\d{2}-\d{2})\/components\/replace-type$/);
      if (replaceMatch && method === 'POST') return await handleReplaceType(request, env, replaceMatch[1]);

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err(`Server error: ${e.message}`, 500);
    }
  },
};
