// nuage-config.js : configuration Firebase de l'application.
// Ce ne sont PAS des secrets : ces valeurs disent seulement quel projet utiliser.
// La sécurité repose sur la connexion (courriel + mot de passe) et sur les règles d'accès
// de Firestore (publication/firestore.rules). La clé est en plus restreinte, dans Google Cloud,
// aux domaines risto72.github.io et localhost, et aux seules API de connexion et de Firestore :
// les appels qui l'utilisent envoient donc le domaine du site (referrerPolicy « strict-origin »).
(function () {
  'use strict';
  const config = {
    apiKey: 'AIzaSyAm5c3UxgymPayDBfwI5-MEa7TssXXsOjc',
    projet: 'epicerie-futee-f14fe',
    auth: 'https://identitytoolkit.googleapis.com/v1',
    jeton: 'https://securetoken.googleapis.com/v1',
    firestore: 'https://firestore.googleapis.com/v1',
  };
  // Tests seulement : sur 127.0.0.1 ou localhost, on peut viser un faux Firebase local
  // (tests/faux-firebase.py). Impossible ailleurs.
  try {
    if (/^(127\.0\.0\.1|localhost)$/.test(location.hostname)) {
      const essai = JSON.parse(localStorage.getItem('epicerie.nuage.essai') || 'null');
      if (essai && /^http:\/\/127\.0\.0\.1:\d+$/.test(essai.base)) {
        config.auth = essai.base + '/auth';
        config.jeton = essai.base + '/jeton';
        config.firestore = essai.base + '/firestore';
      }
    }
  } catch (e) { /* configuration normale */ }
  window.NUAGE_CONFIG = Object.freeze(config);
})();
