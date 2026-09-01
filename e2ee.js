(() => {
  const E2EE_VERSION = 1;
  let e2eePrivateKey = null;
  let e2eeUserId = null;

  const te = new TextEncoder();
  const td = new TextDecoder();
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function passwordKey(password, salt) {
    const material = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptPrivateJwk(jwk, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await passwordKey(password, salt);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(jwk)));
    return { salt: b64(salt), blob: JSON.stringify({ iv: b64(iv), ct: b64(ct) }) };
  }

  async function decryptPrivateJwk(blob, saltText, password) {
    const salt = unb64(saltText);
    const parsed = JSON.parse(blob);
    const key = await passwordKey(password, salt);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(parsed.iv) }, key, unb64(parsed.ct));
    return JSON.parse(td.decode(pt));
  }

  async function importPrivate(jwk) {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  }

  async function importPublic(jwk) {
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  }

  async function deriveShared(otherPublicJwk) {
    if (!e2eePrivateKey) throw new Error('Encrypted messaging is locked. Sign out and sign in again.');
    const otherPublic = await importPublic(otherPublicJwk);
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: otherPublic },
      e2eePrivateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function ensureE2EE(password) {
    if (!user?.id) return;
    const rows = await rest('community_profiles', { q: 'select=id,e2ee_public_key,e2ee_private_key_enc,e2ee_salt&id=eq.' + encodeURIComponent(user.id) });
    const p = rows?.[0];
    if (!p) throw new Error('Save your profile first, then sign in again to activate encrypted messaging.');

    if (p.e2ee_public_key && p.e2ee_private_key_enc && p.e2ee_salt) {
      const privateJwk = await decryptPrivateJwk(p.e2ee_private_key_enc, p.e2ee_salt, password);
      e2eePrivateKey = await importPrivate(privateJwk);
      e2eeUserId = user.id;
      return;
    }

    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const wrapped = await encryptPrivateJwk(priv, password);
    await rest('community_profiles', {
      method: 'PATCH',
      q: 'id=eq.' + encodeURIComponent(user.id),
      body: { e2ee_public_key: pub, e2ee_private_key_enc: wrapped.blob, e2ee_salt: wrapped.salt }
    });
    e2eePrivateKey = pair.privateKey;
    e2eeUserId = user.id;
  }

  async function encryptedSignin() {
    const email = $('email').value.trim().toLowerCase();
    const password = $('password').value;
    if (!email || !password) return status('Enter your email and password.');
    $('signin').disabled = true;
    status('Signing in…');
    try {
      const d = await auth('/auth/v1/token?grant_type=password', { email, password });
      d.expires_at = Date.now() + ((d.expires_in || 3600) * 1000);
      save(d);
      await sync();
      try {
        await ensureE2EE(password);
        status('Signed in. End-to-end encrypted messaging is ready.');
      } catch (e) {
        status('Signed in; encrypted messaging needs attention: ' + e.message);
      }
      await board();
    } catch (e) {
      status(e.message);
    } finally {
      $('signin').disabled = false;
    }
  }

  async function otherUserForConversation(conversationId) {
    const rows = await rest('community_conversations', { q: 'select=*&id=eq.' + encodeURIComponent(conversationId) });
    const c = rows?.[0];
    if (!c || !user) return null;
    return c.user_a === user.id ? c.user_b : c.user_a;
  }

  async function publicKeyFor(uid) {
    const rows = await rest('community_profiles', { q: 'select=id,e2ee_public_key&id=eq.' + encodeURIComponent(uid) });
    return rows?.[0]?.e2ee_public_key || null;
  }

  async function encryptedSend() {
    if (!user || !currentConversation) return;
    const body = $('msg').value.trim();
    if (!body) return;
    try {
      if (!e2eePrivateKey || e2eeUserId !== user.id) throw new Error('Encrypted messaging is locked. Sign out and sign in again.');
      const other = await otherUserForConversation(currentConversation);
      if (!other) throw new Error('Unable to identify the other participant.');
      const otherPub = await publicKeyFor(other);
      if (!otherPub) throw new Error('This member has not activated encrypted messaging yet. They need to sign in once before you can message them.');
      const key = await deriveShared(otherPub);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(body));
      await rest('community_messages', {
        method: 'POST',
        body: {
          conversation_id: currentConversation,
          sender_id: user.id,
          body: '[encrypted:v1]',
          encryption_version: E2EE_VERSION,
          ciphertext: b64(ct),
          iv: b64(iv)
        }
      });
      $('msg').value = '';
      await encryptedMessages();
    } catch (e) {
      $('chattitle').textContent = 'Encrypted message error: ' + e.message;
    }
  }

  async function encryptedMessages() {
    if (!currentConversation || !user) return;
    const d = await rest('community_messages', { q: 'select=*&conversation_id=eq.' + currentConversation + '&order=created_at.asc' });
    const other = await otherUserForConversation(currentConversation);
    const otherPub = other ? await publicKeyFor(other) : null;
    let shared = null;
    if (otherPub && e2eePrivateKey) {
      try { shared = await deriveShared(otherPub); } catch {}
    }
    const rendered = [];
    for (const m of d || []) {
      let text = m.body || '';
      if (m.encryption_version === E2EE_VERSION && m.ciphertext && m.iv) {
        if (!shared) {
          text = '🔒 Encrypted message — sign in again to unlock.';
        } else {
          try {
            const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv) }, shared, unb64(m.ciphertext));
            text = td.decode(pt);
          } catch {
            text = '🔒 Unable to decrypt this message on this account.';
          }
        }
      }
      rendered.push(`<div class="bubble ${m.sender_id === user.id ? 'mine' : ''}">${esc(text)}<div class="meta">${new Date(m.created_at).toLocaleString()}</div></div>`);
    }
    $('chatlog').innerHTML = rendered.join('');
    $('chatlog').scrollTop = $('chatlog').scrollHeight;
  }

  const originalSignout = signout;
  signout = async function () {
    e2eePrivateKey = null;
    e2eeUserId = null;
    return originalSignout();
  };

  signin = encryptedSignin;
  send = encryptedSend;
  messages = encryptedMessages;
  $('signin').onclick = encryptedSignin;
  $('send').onclick = encryptedSend;
})();
