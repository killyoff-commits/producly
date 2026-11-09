// Productly : le webhook Stripe, sur Vercel (POST https://ton-site.vercel.app/api/stripe-webhook).
//
// Stripe l'appelle après chaque paiement. Le serveur vérifie que l'appel vient bien de Stripe (signature),
// puis écrit dans Firestore ce que le joueur a payé :
//   users/{uid}                     le forfait (pro, elite ou free) et l'état de l'abonnement
//   users/{uid}/purchases/{session} chaque achat unique payé (pack, bloc, gel), à donner une seule fois
//   stripeSubscriptions/{id}        quel joueur a quel abonnement (pour les renouvellements et résiliations)
// L'app, connectée au compte, écoute ces documents et donne ce qui a été payé (voir watchEntitlements).
//
// Variables d'environnement à créer dans Vercel (Settings > Environment Variables), jamais dans le code :
//   STRIPE_WEBHOOK_SECRET     whsec_… (Stripe > Développeurs > Webhooks > ton endpoint > Clé secrète de signature)
//   FIREBASE_SERVICE_ACCOUNT  le contenu complet du fichier JSON de la clé de compte de service Firebase
//
// Aucune dépendance à installer : signature, jeton Google et Firestore passent par fetch et Web Crypto (Node 18 ou plus).

// Le prix attendu de chaque achat unique, en centimes. Un montant différent est refusé :
// personne ne peut payer un article à 2,99 € en se faisant livrer un pack à 9,99 €.
export const PRICES = {
  'gel-1': 399,
  'bloc-prism': 299,
  'bloc-titan': 499,
  'bloc-eclipse': 799,
  'pack-midas': 999,
  'pack-dragon': 999,
  'pack-void': 999,
  'pack-nova': 699,
  'pack-cyber': 699,
  'pack-aurora': 699,
  'pack-hudcosmos': 699,
  'pack-hudfauves': 699,
  'pack-hudlegend': 699,
  'pack-hudocean': 699,
  'pack-hudmyth': 699,
  'pack-hudmachine': 699,
};

// Les abonnements se reconnaissent à leur prix mensuel.
export const SUBSCRIPTION_PLANS = { 999: 'pro', 1499: 'elite' };
// Un paiement en retard garde l'accès le temps que Stripe relance ; une résiliation le retire.
const ACTIVE_STATUSES = ['active', 'trialing', 'past_due'];
const SIGNATURE_TOLERANCE_S = 300;
const encoder = new TextEncoder();

const env = (name) => (globalThis.process && process.env && process.env[name]) || '';

// ---------- Signature Stripe ----------
// En-tête Stripe-Signature : t=horodatage,v1=signature. La signature est un HMAC-SHA256 de « t.corps » avec le secret whsec_.
export async function verifyStripeSignature(payload, header, secret, now = Date.now()) {
  if (!header || !secret) return false;
  const parts = header.split(',').map((part) => {
    const index = part.indexOf('=');
    return [part.slice(0, index).trim(), part.slice(index + 1).trim()];
  });
  const timestamp = (parts.find(([key]) => key === 't') || [])[1];
  const signatures = parts.filter(([key]) => key === 'v1').map(([, value]) => value);
  if (!timestamp || !signatures.length) return false;
  // Un vieil appel rejoué ne passe pas.
  if (Math.abs(now / 1000 - Number(timestamp)) > SIGNATURE_TOLERANCE_S) return false;
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(`${timestamp}.${payload}`)));
  const expected = Array.from(mac, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return signatures.some((signature) => sameText(signature, expected));
}

// Comparaison en temps constant : la durée ne révèle rien de la bonne signature.
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}

// ---------- Jeton Google (compte de service) ----------
const base64Url = (bytes) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export async function googleAccessToken(account, fetcher = fetch) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(encoder.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claims = base64Url(encoder.encode(JSON.stringify({
    iss: account.client_email,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })));
  const pem = account.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(pem), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(`${header}.${claims}`)));
  const response = await fetcher('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claims}.${base64Url(signature)}` }).toString(),
  });
  if (!response.ok) throw new Error(`Jeton Google refusé (${response.status}) : ${await response.text()}`);
  return (await response.json()).access_token;
}

// ---------- Firestore (API REST) ----------
function toValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (value instanceof Date) return { timestampValue: value.toISOString() };
  if (typeof value === 'boolean') return { booleanValue: value };
  if (Number.isInteger(value)) return { integerValue: String(value) };
  if (typeof value === 'number') return { doubleValue: value };
  return { stringValue: String(value) };
}

function fromValue(value) {
  if ('stringValue' in value) return value.stringValue;
  if ('integerValue' in value) return Number(value.integerValue);
  if ('doubleValue' in value) return value.doubleValue;
  if ('booleanValue' in value) return value.booleanValue;
  if ('timestampValue' in value) return value.timestampValue;
  return null;
}

// Le jeton n'est demandé qu'au premier accès : un événement ignoré ne coûte rien.
export function firestoreClient(account, fetcher = fetch) {
  let token = null;
  const base = `https://firestore.googleapis.com/v1/projects/${account.project_id}/databases/(default)/documents`;
  const headers = async () => {
    if (!token) token = await googleAccessToken(account, fetcher);
    return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  };
  return {
    async get(path) {
      const response = await fetcher(`${base}/${path}`, { headers: await headers() });
      if (response.status === 404) return null;
      if (!response.ok) throw new Error(`Firestore ${response.status} : ${await response.text()}`);
      const doc = await response.json();
      return Object.fromEntries(Object.entries(doc.fields || {}).map(([name, value]) => [name, fromValue(value)]));
    },
    // Écrit seulement les champs donnés ; mustNotExist : n'écrit rien si le document existe déjà (Stripe renvoie parfois un événement).
    async set(path, data, { mustNotExist = false } = {}) {
      const mask = Object.keys(data).map((name) => `updateMask.fieldPaths=${encodeURIComponent(name)}`).join('&');
      const url = `${base}/${path}?${mask}${mustNotExist ? '&currentDocument.exists=false' : ''}`;
      const response = await fetcher(url, {
        method: 'PATCH',
        headers: await headers(),
        body: JSON.stringify({ fields: Object.fromEntries(Object.entries(data).map(([name, value]) => [name, toValue(value)])) }),
      });
      if (!response.ok) {
        const text = await response.text();
        if (mustNotExist && /ALREADY_EXISTS|FAILED_PRECONDITION|already exists/i.test(text)) return false;
        throw new Error(`Firestore ${response.status} : ${text}`);
      }
      return true;
    },
  };
}

// ---------- Ce que veut dire chaque événement ----------
// client_reference_id, ajouté par l'app au lien de paiement : « uid__type-article » (ex. AbC123__pack-aurora).
export function parseReference(reference) {
  const match = /^([A-Za-z0-9]{1,128})__(plan|pack|bloc|gel)-([a-z0-9]{1,40})$/.exec(reference || '');
  return match ? { uid: match[1], kind: match[2], item: match[3] } : null;
}

export async function handleEvent(event, db) {
  const object = (event.data && event.data.object) || {};
  switch (event.type) {
    case 'checkout.session.completed':
    case 'checkout.session.async_payment_succeeded': {
      // Paiement différé (virement…) : on attend l'événement async_payment_succeeded.
      if (object.payment_status === 'unpaid') return 'paiement pas encore reçu';
      const ref = parseReference(object.client_reference_id);
      if (!ref) return 'paiement sans compte Productly : ignoré';
      const amount = object.amount_subtotal ?? object.amount_total ?? 0;
      if (object.mode === 'subscription') {
        // Le forfait se déduit du prix payé, pas de ce que dit le lien : impossible de payer Pro et d'obtenir Élite.
        const plan = SUBSCRIPTION_PLANS[amount] || (amount === 0 && (ref.item === 'pro' || ref.item === 'elite') ? ref.item : null);
        if (!plan) return `abonnement au montant inconnu (${amount})`;
        await db.set(`users/${ref.uid}`, { plan, planStatus: 'active', subscriptionId: object.subscription || '', customerId: object.customer || '', updatedAt: new Date() });
        if (object.subscription) await db.set(`stripeSubscriptions/${object.subscription}`, { uid: ref.uid, plan, updatedAt: new Date() });
        return `forfait ${plan}`;
      }
      const key = `${ref.kind}-${ref.item}`;
      if (ref.kind === 'plan' || PRICES[key] === undefined) return `article inconnu (${key})`;
      if (amount !== PRICES[key]) return `montant ${amount} au lieu de ${PRICES[key]} pour ${key} : refusé`;
      const created = await db.set(`users/${ref.uid}/purchases/${object.id}`, { kind: ref.kind, item: ref.item, amount, claimed: false, createdAt: new Date() }, { mustNotExist: true });
      return created ? `achat ${key}` : 'achat déjà enregistré';
    }
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const link = await db.get(`stripeSubscriptions/${object.id}`);
      if (!link || !link.uid) return 'abonnement inconnu';
      const price = object.items && object.items.data && object.items.data[0] && object.items.data[0].price;
      const active = event.type !== 'customer.subscription.deleted' && ACTIVE_STATUSES.includes(object.status);
      const plan = active ? (SUBSCRIPTION_PLANS[price && price.unit_amount] || link.plan) : 'free';
      await db.set(`users/${link.uid}`, { plan, planStatus: object.status || 'canceled', subscriptionId: object.id, updatedAt: new Date() });
      if (active) await db.set(`stripeSubscriptions/${object.id}`, { uid: link.uid, plan, updatedAt: new Date() });
      return `forfait ${plan} (${object.status})`;
    }
    default:
      return 'événement ignoré';
  }
}

// ---------- La fonction Vercel ----------
export async function POST(request) {
  const payload = await request.text();
  const valid = await verifyStripeSignature(payload, request.headers.get('stripe-signature'), env('STRIPE_WEBHOOK_SECRET'));
  if (!valid) return new Response('Signature Stripe invalide', { status: 400 });
  let account;
  try {
    account = JSON.parse(env('FIREBASE_SERVICE_ACCOUNT'));
  } catch (error) {
    return new Response('FIREBASE_SERVICE_ACCOUNT manquant ou invalide dans Vercel', { status: 500 });
  }
  try {
    const result = await handleEvent(JSON.parse(payload), firestoreClient(account));
    console.log('Webhook Stripe :', result);
    return Response.json({ received: true, result });
  } catch (error) {
    // Stripe réessaie tout seul pendant plusieurs jours tant que la réponse n'est pas 2xx.
    console.error('Webhook Stripe :', error);
    return new Response('Erreur d\'écriture : Stripe va réessayer', { status: 500 });
  }
}

export function GET() {
  return new Response('Webhook Stripe de Productly : seulement en POST, appelé par Stripe.', { status: 405 });
}
