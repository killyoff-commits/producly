// Productly : le ménage du classement, sur Vercel (GET https://ton-site.vercel.app/api/cleanup).
//
// Vercel l'appelle tout seul chaque nuit (voir "crons" dans vercel.json). Il retire de Firestore :
//   - tout ce qui appartient à un compte qui n'existe plus dans Firebase Authentication (compte Google ou e-mail supprimé) :
//     son score (scores/{uid}), son profil public et ses photos (profiles/{uid}), sa sauvegarde (saves/{uid}) et son pseudo (names/…) ;
//   - un score dont le pseudo n'est pas réservé par ce même compte (deux joueurs au même pseudo) : le vrai propriétaire
//     du pseudo reste, l'autre disparaît du classement jusqu'à ce qu'il choisisse un pseudo libre dans l'app.
// Les achats (users/{uid}) ne sont jamais effacés : ils servent de trace des paiements.
//
// Variables d'environnement Vercel (Settings > Environment Variables) :
//   FIREBASE_SERVICE_ACCOUNT  la même clé de compte de service que pour le webhook Stripe
//   CRON_SECRET               un mot de passe long au hasard que tu inventes : Vercel l'envoie à chaque appel automatique,
//                             et personne d'autre ne peut lancer le ménage
// Pour voir ce qui serait effacé sans rien effacer : ajoute ?dry=1 (avec le même en-tête Authorization).

import { googleAccessToken } from './stripe-webhook.mjs';

const env = (name) => (globalThis.process && process.env && process.env[name]) || '';
const SCOPE = 'https://www.googleapis.com/auth/cloud-platform';

export async function cleanup(account, { dry = false, fetcher = fetch } = {}) {
  const token = await googleAccessToken(account, fetcher, SCOPE);
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  const base = `https://firestore.googleapis.com/v1/projects/${account.project_id}/databases/(default)/documents`;
  const text = (fields, name) => (fields && fields[name] && fields[name].stringValue) || '';

  // Tous les documents d'une collection, page par page (seulement les champs utiles).
  async function list(collection, fields = []) {
    const docs = [];
    let pageToken = '';
    do {
      const mask = fields.map((field) => `&mask.fieldPaths=${encodeURIComponent(field)}`).join('');
      const response = await fetcher(`${base}/${collection}?pageSize=300${mask}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`, { headers });
      if (!response.ok) throw new Error(`Firestore ${collection} ${response.status} : ${await response.text()}`);
      const page = await response.json();
      (page.documents || []).forEach((doc) => docs.push({ id: doc.name.split('/').pop(), fields: doc.fields || {} }));
      pageToken = page.nextPageToken || '';
    } while (pageToken);
    return docs;
  }

  async function remove(path) {
    if (dry) return;
    const response = await fetcher(`${base}/${path}`, { method: 'DELETE', headers });
    if (!response.ok && response.status !== 404) throw new Error(`Suppression ${path} ${response.status} : ${await response.text()}`);
  }

  const [scores, profiles, saves, names] = await Promise.all([
    list('scores', ['name', 'nameKey']),
    list('profiles', ['name']),
    list('saves', ['v']),
    list('names', ['uid']),
  ]);

  // Les comptes qui existent encore, demandés à Firebase Authentication par lots de 100.
  const uids = [...new Set([...scores, ...profiles, ...saves].map((doc) => doc.id).concat(names.map((doc) => text(doc.fields, 'uid')).filter(Boolean)))];
  const alive = new Set();
  for (let index = 0; index < uids.length; index += 100) {
    const response = await fetcher(`https://identitytoolkit.googleapis.com/v1/projects/${account.project_id}/accounts:lookup`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ localId: uids.slice(index, index + 100) }),
    });
    if (!response.ok) throw new Error(`Firebase Authentication ${response.status} : ${await response.text()}`);
    ((await response.json()).users || []).forEach((user) => alive.add(user.localId));
  }

  const report = { comptesSupprimes: [], pseudosEnDouble: [] };
  const gone = uids.filter((uid) => !alive.has(uid));
  for (const uid of gone) {
    report.comptesSupprimes.push(uid);
    await remove(`scores/${uid}`);
    await remove(`saves/${uid}`);
    if (profiles.some((doc) => doc.id === uid)) {
      for (const photo of await list(`profiles/${uid}/photos`)) await remove(`profiles/${uid}/photos/${photo.id}`);
      await remove(`profiles/${uid}`);
    }
  }
  for (const name of names) {
    if (!alive.has(text(name.fields, 'uid'))) await remove(`names/${name.id}`);
  }
  // Un score n'a sa place que si son pseudo est réservé par ce même compte.
  const owners = new Map(names.map((doc) => [doc.id, text(doc.fields, 'uid')]));
  for (const score of scores) {
    if (!alive.has(score.id)) continue;
    const key = text(score.fields, 'nameKey');
    if (!key || owners.get(key) !== score.id) {
      report.pseudosEnDouble.push(`${score.id} (${text(score.fields, 'name')})`);
      await remove(`scores/${score.id}`);
    }
  }
  return report;
}

export async function GET(request) {
  const secret = env('CRON_SECRET');
  if (!secret) return new Response('CRON_SECRET manquant dans Vercel', { status: 500 });
  if (request.headers.get('authorization') !== `Bearer ${secret}`) return new Response('Accès refusé', { status: 401 });
  let account;
  try {
    account = JSON.parse(env('FIREBASE_SERVICE_ACCOUNT'));
  } catch (error) {
    return new Response('FIREBASE_SERVICE_ACCOUNT manquant ou invalide dans Vercel', { status: 500 });
  }
  const dry = new URL(request.url).searchParams.get('dry') === '1';
  try {
    const report = await cleanup(account, { dry });
    console.log('Ménage du classement :', JSON.stringify(report));
    return Response.json({ dry, ...report });
  } catch (error) {
    console.error('Ménage du classement :', error);
    return new Response(`Erreur : ${error.message}`, { status: 500 });
  }
}
