<script>
  import { onMount } from 'svelte';
  import { api, getCsrf, setCsrf, clearCsrf } from './lib/api.js';

  let theme = $state('light');
  let initialized = $state(false);
  let unlocked = $state(false);
  let route = $state('vault');

  let entries = $state([]);
  let revealed = $state({});
  let values = $state({});
  let search = $state('');

  let toast = $state({ msg: '', kind: '', visible: false });
  let toastTimer;

  // auth forms
  let showSetupPw = $state(false);
  let showSetupPw2 = $state(false);
  let setupPw = $state('');
  let setupPw2 = $state('');
  let setupErr = $state('');

  let showUnlockPw = $state(false);
  let unlockPw = $state('');
  let remember = $state(false);
  let unlockErr = $state('');

  // add modal
  let addModalOpen = $state(false);
  let newName = $state('');
  let newValue = $state('');

  // settings
  let showCpCur = $state(false);
  let showCpNew = $state(false);
  let showCpNew2 = $state(false);
  let cpCur = $state('');
  let cpNew = $state('');
  let cpNew2 = $state('');
  let audit = $state([]);

  let loadingEntries = $state(false);

  function showToast(msg, kind = '') {
    toast = { msg, kind, visible: true };
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast = { ...toast, visible: false };
    }, 2600);
  }

  function applyTheme(t) {
    theme = t;
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('theme', t); } catch (e) { /* ignore */ }
  }
  function toggleTheme() {
    applyTheme(theme === 'dark' ? 'light' : 'dark');
  }

  function syncRoute() {
    route = (typeof location !== 'undefined' && location.hash === '#/settings') ? 'settings' : 'vault';
    if (unlocked && route === 'settings') loadAudit();
  }

  async function refreshStatus() {
    const s = await api('/api/status');
    if (s.data) {
      initialized = !!s.data.initialized;
      unlocked = !!s.data.unlocked;
    }
  }

  async function refreshEntries() {
    loadingEntries = true;
    const res = await api('/api/entries');
    entries = (res.data && res.data.entries) || [];
    loadingEntries = false;
  }

  async function doSetup() {
    setupErr = '';
    if (setupPw.length < 8) { setupErr = 'Password must be at least 8 characters'; return; }
    if (setupPw !== setupPw2) { setupErr = 'Passwords do not match'; return; }
    const r = await api('/api/setup', 'POST', { password: setupPw, confirm: setupPw2 });
    if (r.ok) {
      if (r.data && r.data.csrf) setCsrf(r.data.csrf);
      initialized = true;
      unlocked = true;
      setupPw = ''; setupPw2 = '';
      await refreshEntries();
      showToast('Vault created', 'ok');
    } else {
      setupErr = (r.data && r.data.error) || 'error';
    }
  }

  async function doUnlock() {
    unlockErr = '';
    const r = await api('/api/unlock', 'POST', { password: unlockPw, remember });
    if (r.ok) {
      if (r.data && r.data.csrf) setCsrf(r.data.csrf);
      unlocked = true;
      unlockPw = '';
      await refreshEntries();
      showToast('Unlocked', 'ok');
    } else {
      unlockErr = (r.data && r.data.error) || 'error';
    }
  }

  async function doLock() {
    await api('/api/lock', 'POST');
    clearCsrf();
    unlocked = false;
    revealed = {};
    values = {};
    entries = [];
    audit = [];
    if (location.hash === '#/settings') location.hash = '';
    showToast('Locked', 'ok');
  }

  let filtered = $derived.by(() => {
    const q = search.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((name) => {
      if (name.toLowerCase().includes(q)) return true;
      if (revealed[name] && (values[name] || '').toLowerCase().includes(q)) return true;
      return false;
    });
  });

  async function toggleReveal(name) {
    if (revealed[name]) {
      revealed = { ...revealed, [name]: false };
      return;
    }
    const r = await api('/api/entries/' + encodeURIComponent(name));
    if (r.ok) {
      values = { ...values, [name]: r.data.value };
      revealed = { ...revealed, [name]: true };
    } else {
      showToast((r.data && r.data.error) || 'error', 'err');
    }
  }

  async function copyValue(name) {
    try {
      await navigator.clipboard.writeText(values[name]);
      showToast('copied to clipboard', 'ok');
    } catch (e) {
      showToast('copy failed', 'err');
    }
  }

  async function deleteEntry(name) {
    if (!confirm("Delete entry '" + name + "'?")) return;
    const r = await api('/api/entries/' + encodeURIComponent(name), 'DELETE');
    if (r.ok) {
      const nr = { ...revealed }; delete nr[name]; revealed = nr;
      const nv = { ...values }; delete nv[name]; values = nv;
      showToast('deleted', 'ok');
      await refreshEntries();
    } else {
      showToast((r.data && r.data.error) || 'error', 'err');
    }
  }

  async function saveEntry() {
    const name = newName.trim();
    if (!name) { showToast('Name is required', 'err'); return; }
    if (newValue === '') { showToast('Value is required', 'err'); return; }
    const r = await api('/api/entries', 'POST', { name, value: newValue });
    if (r.ok) {
      addModalOpen = false;
      newName = '';
      newValue = '';
      showToast('Saved', 'ok');
      await refreshEntries();
    } else {
      showToast((r.data && r.data.error) || 'error', 'err');
    }
  }

  async function changePassword() {
    if (cpNew !== cpNew2) { showToast('New passwords do not match', 'err'); return; }
    const r = await api('/api/change-password', 'POST', { current: cpCur, new: cpNew, confirm: cpNew2 });
    if (r.ok) {
      cpCur = ''; cpNew = ''; cpNew2 = '';
      showToast('Password changed', 'ok');
    } else {
      showToast((r.data && r.data.error) || 'error', 'err');
    }
  }

  async function loadAudit() {
    const r = await api('/api/audit?n=100');
    if (r.ok) audit = (r.data && r.data.entries) || [];
    else showToast((r.data && r.data.error) || 'error', 'err');
  }

  onMount(async () => {
    try {
      const saved = localStorage.getItem('theme');
      if (saved) theme = saved;
      else if (window.matchMedia('(prefers-color-scheme: dark)').matches) theme = 'dark';
    } catch (e) { /* ignore */ }
    applyTheme(theme);

    syncRoute();
    window.addEventListener('hashchange', syncRoute);

    await refreshStatus();
    if (unlocked) await refreshEntries();
  });
</script>

<header class="utility">
  <div class="u-inner">
    <div class="u-brand">
      <img class="u-mark" src="/favicon.svg" alt="Kinko" />
      <span class="u-name">Kinko 金庫</span>
    </div>
    <div class="u-right">
      <button class="u-link" onclick={toggleTheme} title="toggle theme">{theme === 'dark' ? 'Light' : 'Dark'}</button>
      {#if unlocked}
        <a class="u-link" href="#/settings">Settings</a>
        <button class="u-link" onclick={doLock}>Lock</button>
      {/if}
    </div>
  </div>
  <nav class="u-subnav">
    <div class="status-pill {unlocked ? 'unlocked' : initialized ? 'locked' : ''}">
      <span class="status-dot"></span>
      <span>{unlocked ? 'unlocked' : initialized ? 'locked' : 'not set'}</span>
    </div>
  </nav>
</header>

<main>
  {#if !initialized}
    <section class="auth">
      <div class="auth-card">
        <div class="mark">🔐</div>
        <h2>Create your vault</h2>
        <div class="sub">Choose a strong master password. It is never stored — lose it and the data is unrecoverable.</div>
        <div class="field">
          <label for="setupPw">Master password</label>
          <div class="input-wrap">
            <input id="setupPw" type={showSetupPw ? 'text' : 'password'} bind:value={setupPw} class="input" autocomplete="new-password" placeholder="at least 8 characters" />
            <button type="button" class="pw-toggle" onclick={() => (showSetupPw = !showSetupPw)}>{showSetupPw ? 'hide' : 'show'}</button>
          </div>
        </div>
        <div class="field">
          <label for="setupPw2">Confirm password</label>
          <div class="input-wrap">
            <input id="setupPw2" type={showSetupPw2 ? 'text' : 'password'} bind:value={setupPw2} class="input" autocomplete="new-password" placeholder="repeat password" />
            <button type="button" class="pw-toggle" onclick={() => (showSetupPw2 = !showSetupPw2)}>{showSetupPw2 ? 'hide' : 'show'}</button>
          </div>
        </div>
        <button class="btn cta" onclick={doSetup}>Create vault</button>
        {#if setupErr}<div class="err-msg">{setupErr}</div>{/if}
      </div>
    </section>
  {:else if !unlocked}
    <section class="auth">
      <div class="auth-card">
        <div class="mark">🔐</div>
        <h2>Unlock vault</h2>
        <div class="sub">Enter your master password to access your credentials.</div>
        <div class="field">
          <label for="unlockPw">Master password</label>
          <div class="input-wrap">
            <input id="unlockPw" type={showUnlockPw ? 'text' : 'password'} bind:value={unlockPw} class="input" autocomplete="current-password" placeholder="master password" onkeydown={(e) => { if (e.key === 'Enter') doUnlock(); }} />
            <button type="button" class="pw-toggle" onclick={() => (showUnlockPw = !showUnlockPw)}>{showUnlockPw ? 'hide' : 'show'}</button>
          </div>
        </div>
        <label class="remember"><input type="checkbox" bind:checked={remember} />Remember me (30 days)</label>
        <button class="btn cta" onclick={doUnlock}>Unlock</button>
        {#if unlockErr}<div class="err-msg">{unlockErr}</div>{/if}
      </div>
    </section>
  {:else if route === 'settings'}
    <section class="plate">
      <div class="auth-card" style="max-width:620px;margin:0 auto">
        <div class="mark">🔐</div>
        <h2>Settings</h2>
        <div class="sub">Manage your vault configuration.</div>

        <div class="field" style="margin-top:20px">
          <label for="cpCur">Current password</label>
          <div class="input-wrap">
            <input id="cpCur" type={showCpCur ? 'text' : 'password'} bind:value={cpCur} class="input" placeholder="current password" />
            <button type="button" class="pw-toggle" onclick={() => (showCpCur = !showCpCur)}>{showCpCur ? 'hide' : 'show'}</button>
          </div>
        </div>
        <div class="field">
          <label for="cpNew">New password</label>
          <div class="input-wrap">
            <input id="cpNew" type={showCpNew ? 'text' : 'password'} bind:value={cpNew} class="input" placeholder="new password" />
            <button type="button" class="pw-toggle" onclick={() => (showCpNew = !showCpNew)}>{showCpNew ? 'hide' : 'show'}</button>
          </div>
        </div>
        <div class="field">
          <label for="cpNew2">Confirm new</label>
          <div class="input-wrap">
            <input id="cpNew2" type={showCpNew2 ? 'text' : 'password'} bind:value={cpNew2} class="input" placeholder="confirm" />
            <button type="button" class="pw-toggle" onclick={() => (showCpNew2 = !showCpNew2)}>{showCpNew2 ? 'hide' : 'show'}</button>
          </div>
        </div>
        <button class="btn cta" onclick={changePassword} style="width:100%">Change password</button>

        <div class="label" style="margin:28px 0 12px">Session</div>
        <p class="muted" style="font-size:13px;margin-bottom:16px">Sessions persist across restarts. Tick "Remember me" on the unlock screen to stay signed in for 30 days.</p>
        <button class="btn danger" onclick={doLock} style="width:100%">Lock vault</button>
        <div style="margin-top:14px"><a class="btn ghost sm" href="#/">← Back to vault</a></div>

        <div class="label" style="margin:28px 0 12px">Audit log (last 100)</div>
        <div class="entries">
          {#each audit as a (a.ts + (a.name || '') + (a.action || ''))}
            <div class="entry">
              <div class="entry-top">
                <div class="entry-key">{a.ts}</div>
              </div>
              <div class="entry-bottom">
                <div class="entry-val revealed">{a.action} {a.name ? '· ' + a.name : ''} <span class="decision">— {a.decision}{a.reason ? ' (' + a.reason + ')' : ''}</span></div>
              </div>
            </div>
          {/each}
          {#if audit.length === 0}
            <div class="empty-state"><div class="ico">📜</div><p>No audit entries.</p></div>
          {/if}
        </div>
      </div>
    </section>
  {:else}
    <div class="ticker">
      <div class="track">
        <span>AES-256-GCM</span><span class="dot">✦</span><span>PBKDF2 · 600k</span><span class="dot">✦</span><span>LOCALHOST ONLY</span><span class="dot">✦</span><span>ZERO-KNOWLEDGE</span><span class="dot">✦</span><span>SESSION-SAFE</span><span class="dot">✦</span>
        <span>AES-256-GCM</span><span class="dot">✦</span><span>PBKDF2 · 600k</span><span class="dot">✦</span><span>LOCALHOST ONLY</span><span class="dot">✦</span><span>ZERO-KNOWLEDGE</span><span class="dot">✦</span><span>SESSION-SAFE</span><span class="dot">✦</span>
      </div>
    </div>
    <div class="plate">
      <div class="plate-head">
        <div class="eyebrow">MEET THE VAULT</div>
        <h2>Every key, one encrypted shelf.</h2>
        <p>Store API keys, tokens, and passwords as named entries. Reveal, copy, or delete on demand — values are decrypted only when you ask.</p>
      </div>
      <div class="bordered vault-panel">
        <div class="vault-head">
          <div>
            <div class="title">Entries</div>
            <div class="sub">{filtered.length} of {entries.length} entries</div>
          </div>
          <div class="search-wrap">
            <input type="text" bind:value={search} class="input" placeholder="search entries…" autocomplete="off" />
          </div>
          <button class="btn cta sm" onclick={() => (addModalOpen = true)}>＋ Add entry</button>
        </div>
        <div class="entries">
          {#each filtered as name, i (name)}
            <div class="entry" style="animation-delay:{i * 45}ms">
              <div class="entry-top">
                <div class="entry-key">{name}</div>
              </div>
              <div class="entry-bottom">
                <div class="entry-val {revealed[name] ? 'revealed' : ''}">{revealed[name] ? (values[name] ?? '••••••••') : '••••••••'}</div>
                <div class="entry-actions">
                  <button class="icon-btn" title={revealed[name] ? 'hide' : 'reveal'} onclick={() => toggleReveal(name)}>{revealed[name] ? '🙈' : '👁'}</button>
                  <button class="icon-btn" title="copy" disabled={!revealed[name]} onclick={() => copyValue(name)}>⧉</button>
                  <button class="icon-btn danger" title="delete" onclick={() => deleteEntry(name)}>✕</button>
                </div>
              </div>
            </div>
          {/each}
        </div>
        {#if entries.length === 0 || (search.trim() && filtered.length === 0)}
          <div class="empty-state">
            <div class="ico">🔐</div>
            <p>{search.trim() && filtered.length === 0 ? 'No entries match "' + search.trim() + '".' : 'No entries yet. Click "Add entry" to create your first one.'}</p>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</main>

{#if addModalOpen}
  <div class="modal">
    <div class="modal-backdrop" role="button" tabindex="0" onclick={() => (addModalOpen = false)} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') addModalOpen = false; }}></div>
    <div class="modal-card bordered">
      <div class="vault-head">
        <div class="title">Add / update entry</div>
        <button class="icon-btn" onclick={() => (addModalOpen = false)} title="close">✕</button>
      </div>
      <div style="padding:22px">
        <div class="field">
          <label for="newName">Name</label>
          <input id="newName" type="text" bind:value={newName} class="input mono" placeholder="e.g. github_api_key" />
        </div>
        <div class="field">
          <label for="newValue">Value</label>
          <input id="newValue" type="text" bind:value={newValue} class="input mono" placeholder="secret value" />
        </div>
        <div style="display:flex;gap:10px;margin-top:20px">
          <button class="btn cta" onclick={saveEntry} style="flex:1">Save entry</button>
          <button class="btn ghost" onclick={() => (addModalOpen = false)} style="flex:1">Cancel</button>
        </div>
      </div>
    </div>
  </div>
{/if}

<div class="toast {toast.visible ? 'show' : ''} {toast.kind}">{#if toast.visible}<span>{toast.kind === 'err' ? '✕' : toast.kind === 'ok' ? '✓' : 'ℹ'}</span><span>{toast.msg}</span>{/if}</div>