// deverrouiller.js : page de connexion, puis ouverture de l'application chiffrée.
//
// Le code de l'application est chiffré par publier.sh (openssl, AES-256-CBC). La clé (48 octets :
// clé + IV, tirée par PBKDF2-SHA256 de la phrase de passe interne) est rangée dans Firestore,
// document cles/application, champ « m », lisible SEULEMENT par un compte connecté.
//
// Connexion : courriel + mot de passe (Firebase Authentication, API REST, sans bibliothèque).
// L'appareil garde la session (jeton de renouvellement) et la clé : il s'ouvre ensuite sans
// redemander, même hors ligne. « Se déconnecter » (dans l'application) efface les deux.
(function () {
  'use strict';

  const NUAGE = window.NUAGE_CONFIG;
  const CLE_STOCKAGE = 'epicerie.cle';
  const SESSION_STOCKAGE = 'epicerie.session';
  const MARQUE = 'epicerie-futee';

  const $ = (id) => document.getElementById(id);
  const form = $('form-coffre');
  const erreur = $('erreur-coffre');
  const info = $('info-coffre');

  function versOctets(b64) {
    const s = atob(b64);
    const o = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i);
    return o;
  }
  function hex(octets) { return Array.from(octets, (b) => b.toString(16).padStart(2, '0')).join(''); }

  const brut = versOctets($('contenu-chiffre').textContent.trim());
  const entete = new TextDecoder().decode(brut.slice(0, 8));
  if (entete !== 'Salted__') { erreur.textContent = 'Le contenu de la page est abîmé.'; form.hidden = false; return; }
  const selHex = hex(brut.slice(8, 16));
  const chiffre = brut.slice(16);

  async function dechiffrer(materiel) {
    const cle = await crypto.subtle.importKey('raw', materiel.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']);
    const clair = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: materiel.slice(32, 48) }, cle, chiffre);
    const paquet = JSON.parse(new TextDecoder().decode(clair));
    if (!paquet || paquet.marque !== MARQUE) throw new Error('marque');
    return paquet;
  }

  function lancer(paquet) {
    const styleCoffre = $('style-coffre');
    if (styleCoffre) styleCoffre.remove();
    document.body.className = '';
    const style = document.createElement('style');
    style.textContent = paquet.css;
    document.head.appendChild(style);
    document.body.innerHTML = paquet.html; // contenu à nous, déchiffré, jamais du texte de circulaire
    const url = URL.createObjectURL(new Blob([paquet.js], { type: 'text/javascript' }));
    const script = document.createElement('script');
    script.src = url;
    document.body.appendChild(script);
  }

  function lire(cle) { try { return JSON.parse(localStorage.getItem(cle) || 'null'); } catch (e) { return null; } }
  function ecrire(cle, v) { try { localStorage.setItem(cle, JSON.stringify(v)); } catch (e) { /* rien */ } }
  function oublier(cle) { try { localStorage.removeItem(cle); } catch (e) { /* rien */ } }

  // Messages d'erreur de Firebase Authentication, en clair.
  function messageAuth(code) {
    const c = String(code || '');
    if (/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND|INVALID_EMAIL/.test(c)) return 'Courriel ou mot de passe incorrect.';
    if (/USER_DISABLED/.test(c)) return 'Ce compte est désactivé.';
    if (/TOO_MANY_ATTEMPTS/.test(c)) return 'Trop d’essais. Attends quelques minutes, puis réessaie.';
    if (/MISSING_PASSWORD/.test(c)) return 'Entre ton mot de passe.';
    return 'Connexion impossible (' + c + ').';
  }

  async function appelAuth(chemin, corps) {
    let r;
    try {
      r = await fetch(NUAGE.auth + '/' + chemin + '?key=' + encodeURIComponent(NUAGE.apiKey), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Firebase-Locale': 'fr' },
        body: JSON.stringify(corps),
        credentials: 'omit',
        // Seulement le domaine du site (ex. https://risto72.github.io/) : la clé API Firebase est
        // restreinte à ce domaine dans Google Cloud. Rien d'autre n'est indiqué.
        referrerPolicy: 'strict-origin',
      });
    } catch (e) {
      throw new Error('Pas de connexion Internet. Réessaie quand le réseau revient.');
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(messageAuth(data && data.error && data.error.message));
    return data;
  }

  async function lireCleDistante(idToken) {
    const url = NUAGE.firestore + '/projects/' + encodeURIComponent(NUAGE.projet) + '/databases/(default)/documents/cles/application';
    let r;
    try {
      r = await fetch(url, { headers: { Authorization: 'Bearer ' + idToken }, credentials: 'omit', referrerPolicy: 'no-referrer' });
    } catch (e) {
      throw new Error('Pas de connexion Internet. Réessaie quand le réseau revient.');
    }
    if (r.status === 403) throw new Error('Ce compte n’a pas accès à l’application.');
    if (r.status === 404) throw new Error('La clé de l’application n’est pas encore installée dans Firebase.');
    if (!r.ok) throw new Error('Firebase ne répond pas (' + r.status + '). Réessaie plus tard.');
    const doc = await r.json();
    const m = doc && doc.fields && doc.fields.m && doc.fields.m.stringValue;
    if (!m) throw new Error('La clé de l’application est incomplète dans Firebase.');
    return versOctets(m.trim());
  }

  // Afficher ou masquer le mot de passe pendant qu'on le tape.
  const voir = $('btn-voir');
  voir.addEventListener('click', () => {
    const champ = $('phrase');
    const visible = champ.type === 'password';
    champ.type = visible ? 'text' : 'password';
    voir.textContent = visible ? 'Masquer' : 'Afficher';
    voir.setAttribute('aria-pressed', visible ? 'true' : 'false');
    champ.focus();
  });

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const bouton = $('btn-ouvrir');
    const courriel = $('courriel').value.trim();
    const motDePasse = $('phrase').value;
    if (!courriel || !motDePasse) return;
    // On remasque avant d'envoyer, pour que le gestionnaire de mots de passe reconnaisse le champ.
    $('phrase').type = 'password';
    voir.textContent = 'Afficher';
    voir.setAttribute('aria-pressed', 'false');
    bouton.disabled = true;
    bouton.textContent = 'Connexion…';
    erreur.textContent = '';
    info.textContent = '';
    try {
      const s = await appelAuth('accounts:signInWithPassword', { email: courriel, password: motDePasse, returnSecureToken: true });
      const materiel = await lireCleDistante(s.idToken);
      const paquet = await dechiffrer(materiel).catch(() => { throw new Error('La clé dans Firebase ne correspond pas à cette version de l’application.'); });
      ecrire(SESSION_STOCKAGE, {
        uid: s.localId, courriel: s.email || courriel, renouvellement: s.refreshToken,
        jeton: s.idToken, expire: Date.now() + (Number(s.expiresIn) || 3600) * 1000,
      });
      ecrire(CLE_STOCKAGE, { sel: selHex, m: btoa(String.fromCharCode.apply(null, materiel)) });
      lancer(paquet);
    } catch (e) {
      erreur.textContent = e.message || 'Connexion impossible.';
      bouton.disabled = false;
      bouton.textContent = 'Se connecter';
    }
  });

  $('btn-oubli').addEventListener('click', async () => {
    const courriel = $('courriel').value.trim();
    erreur.textContent = '';
    if (!courriel) { erreur.textContent = 'Entre d’abord ton courriel, puis touche « Mot de passe oublié ? ».'; $('courriel').focus(); return; }
    try {
      await appelAuth('accounts:sendOobCode', { requestType: 'PASSWORD_RESET', email: courriel });
    } catch (e) { /* même message, pour ne pas révéler si le compte existe */ }
    info.textContent = 'Si ce courriel a un compte, un lien pour choisir un nouveau mot de passe vient d’être envoyé. Vérifie aussi les indésirables.';
  });

  (async () => {
    if (!window.crypto || !crypto.subtle || !NUAGE) {
      erreur.textContent = 'Ce navigateur ne permet pas d’ouvrir l’application. Utilise Safari.';
      form.hidden = false;
      return;
    }
    // Ouverture directe si l'appareil a une session ET la clé de cette version.
    const session = lire(SESSION_STOCKAGE);
    const cle = lire(CLE_STOCKAGE);
    if (session && session.uid && cle && cle.sel === selHex && cle.m) {
      try { lancer(await dechiffrer(versOctets(cle.m))); return; }
      catch (e) { oublier(CLE_STOCKAGE); }
    }
    // Ancienne version (phrase de passe) : la clé seule ne suffit plus, il faut se connecter.
    form.hidden = false;
    if (session && session.courriel) $('courriel').value = session.courriel;
    ($('courriel').value ? $('phrase') : $('courriel')).focus();
  })();
})();
