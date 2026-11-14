// deverrouiller.js : ouvre l'application chiffrée.
// Le contenu est chiffré par publier.sh (openssl, AES-256-CBC, clé tirée de la phrase
// de passe par PBKDF2-SHA256). Sans la phrase de passe, la page publiée est illisible.
// Une fois la bonne phrase entrée, la clé dérivée (pas la phrase) est gardée sur l'appareil.
(function () {
  'use strict';

  const ITERATIONS = 600000;
  const CLE_STOCKAGE = 'epicerie.cle';
  const MARQUE = 'epicerie-futee';

  const $ = (id) => document.getElementById(id);
  const form = $('form-coffre');
  const erreur = $('erreur-coffre');

  function versOctets(b64) {
    const s = atob(b64);
    const o = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i);
    return o;
  }
  function versB64(octets) { return btoa(String.fromCharCode.apply(null, octets)); }
  function hex(octets) { return Array.from(octets, (b) => b.toString(16).padStart(2, '0')).join(''); }

  const brut = versOctets($('contenu-chiffre').textContent.trim());
  const entete = new TextDecoder().decode(brut.slice(0, 8));
  if (entete !== 'Salted__') { erreur.textContent = 'Le contenu de la page est abîmé.'; form.hidden = false; return; }
  const sel = brut.slice(8, 16);
  const chiffre = brut.slice(16);
  const selHex = hex(sel);

  async function deriver(phrase) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(phrase.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: sel, iterations: ITERATIONS }, base, 384);
    return new Uint8Array(bits);
  }

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

  function lireCle() {
    try {
      const v = JSON.parse(localStorage.getItem(CLE_STOCKAGE) || 'null');
      return v && v.sel === selHex ? versOctets(v.m) : null;
    } catch (e) { return null; }
  }
  function garderCle(materiel) {
    try { localStorage.setItem(CLE_STOCKAGE, JSON.stringify({ sel: selHex, m: versB64(materiel) })); } catch (e) { /* on redemandera */ }
  }
  function oublierCle() {
    try { localStorage.removeItem(CLE_STOCKAGE); } catch (e) { /* rien */ }
  }

  // Afficher ou masquer la phrase pendant qu'on la tape.
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
    const phrase = $('phrase').value;
    if (!phrase) return;
    // On remasque avant d'ouvrir, pour que le gestionnaire de mots de passe reconnaisse le champ.
    $('phrase').type = 'password';
    voir.textContent = 'Afficher';
    voir.setAttribute('aria-pressed', 'false');
    bouton.disabled = true;
    bouton.textContent = 'Ouverture…';
    erreur.textContent = '';
    try {
      const materiel = await deriver(phrase);
      const paquet = await dechiffrer(materiel);
      garderCle(materiel);
      lancer(paquet);
    } catch (e) {
      erreur.textContent = 'Phrase de passe incorrecte. Vérifie les majuscules et les espaces.';
      bouton.disabled = false;
      bouton.textContent = 'Déverrouiller';
      $('phrase').select();
    }
  });

  (async () => {
    if (!window.crypto || !crypto.subtle) {
      erreur.textContent = 'Ce navigateur ne permet pas d’ouvrir l’application. Utilise Safari.';
      form.hidden = false;
      return;
    }
    const memorisee = lireCle();
    if (memorisee) {
      try { lancer(await dechiffrer(memorisee)); return; }
      catch (e) { oublierCle(); }
    }
    form.hidden = false;
    $('phrase').focus();
  })();
})();
