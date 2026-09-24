// packages/azione/src/main.ts
import { tmpdir as tmpdir2 } from "node:os";
import { join as join2 } from "node:path";

// packages/cervello/src/contromutazione/applica.ts
function applicaMutazione(sorgente, m) {
  if (m.cerca === "" || m.cerca === m.sostituisci) return null;
  if (m.riga === void 0) {
    const i2 = sorgente.indexOf(m.cerca);
    if (i2 < 0) return null;
    return sorgente.slice(0, i2) + m.sostituisci + sorgente.slice(i2 + m.cerca.length);
  }
  const righe = sorgente.split("\n");
  const r = righe[m.riga - 1];
  if (r === void 0) return null;
  const i = r.indexOf(m.cerca);
  if (i < 0) return null;
  righe[m.riga - 1] = r.slice(0, i) + m.sostituisci + r.slice(i + m.cerca.length);
  return righe.join("\n");
}

// packages/app/src/protocollo.ts
var LIMITI = {
  ordineByte: 4 * 1024 * 1024,
  corse: 64,
  rapportoByte: 4 * 1024 * 1024,
  /** Oltre, una stringa del rapporto (una traccia dello stack) si accorcia: il servizio ne legge il prefisso. */
  stringa: 4096
};
var testo = (x) => typeof x === "string";
var oggetto = (x) => typeof x === "object" && x !== null && !Array.isArray(x);
var dizionarioDiTesti = (x) => oggetto(x) && Object.values(x).every(testo);
function \u00E8Toppa(x) {
  return oggetto(x) && testo(x.file) && testo(x.cerca) && testo(x.sostituisci) && (x.riga === void 0 || typeof x.riga === "number");
}
function \u00E8Ordine(x) {
  if (!oggetto(x)) return false;
  return testo(x.id) && testo(x.contratto) && testo(x.sha) && typeof x.scadeIl === "number" && dizionarioDiTesti(x.scrivi) && Array.isArray(x.corse) && x.corse.every(
    (c) => oggetto(c) && testo(c.id) && Array.isArray(c.toppe) && c.toppe.every(\u00E8Toppa) && (c.soloFile === void 0 || Array.isArray(c.soloFile) && c.soloFile.every(testo))
  ) && Array.isArray(x.leggi) && x.leggi.every(testo) && Array.isArray(x.impronta) && x.impronta.every(testo);
}
function \u00E8Risultati(x) {
  if (!oggetto(x)) return false;
  return testo(x.ordine) && testo(x.contratto) && testo(x.commit) && testo(x.repository) && testo(x.radice) && Array.isArray(x.corse) && x.corse.every(
    (c) => oggetto(c) && testo(c.id) && typeof c.applicata === "boolean" && typeof c.eseguitaIl === "number" && (c.impronte === void 0 || dizionarioDiTesti(c.impronte))
  ) && oggetto(x.letti) && Object.values(x.letti).every((v) => v === null || testo(v)) && (x.impronte === void 0 || dizionarioDiTesti(x.impronte)) && (x.dichiarazione === void 0 || oggetto(x.dichiarazione) && typeof x.dichiarazione.usoAI === "boolean");
}

// packages/verifica/src/crypto-node.ts
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify
} from "node:crypto";

// packages/verifica/src/impronta.ts
function decodificaHex(hex) {
  if (hex.length % 2 !== 0)
    throw new Error(`decodificaHex: ${hex.length} caratteri, un esadecimale ne ha un numero pari`);
  if (!/^[0-9a-fA-F]*$/.test(hex))
    throw new Error("decodificaHex: il testo contiene caratteri che non sono esadecimali");
  const byte = new Uint8Array(hex.length / 2);
  for (let i = 0; i < byte.length; i++) byte[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return byte;
}

// packages/verifica/src/crypto-node.ts
var PREFISSO_PKCS8 = decodificaHex("302e020100300506032b657004220420");
var PREFISSO_SPKI = decodificaHex("302a300506032b6570032100");
var BYTE_CHIAVE = 32;
function esigi32(chiave, quale) {
  if (chiave.length !== BYTE_CHIAVE)
    throw new Error(
      `crittografiaNode: la chiave ${quale} \xE8 di ${chiave.length} byte, ed25519 ne vuole ${BYTE_CHIAVE}`
    );
}
var chiavePrivataDa = (raw) => createPrivateKey({ key: Buffer.concat([PREFISSO_PKCS8, raw]), format: "der", type: "pkcs8" });
var chiavePubblicaDa = (raw) => createPublicKey({ key: Buffer.concat([PREFISSO_SPKI, raw]), format: "der", type: "spki" });
var crittografiaNode = {
  sha256Hex(testo2) {
    return createHash("sha256").update(testo2, "utf8").digest("hex");
  },
  firma(messaggio, chiavePrivata) {
    esigi32(chiavePrivata, "privata");
    return new Uint8Array(sign(null, messaggio, chiavePrivataDa(chiavePrivata)));
  },
  /** Una chiave storta o una firma della lunghezza sbagliata sono una verifica FALSA, non un'eccezione. */
  verifica(messaggio, firma, chiavePubblica) {
    try {
      esigi32(chiavePubblica, "pubblica");
      return verify(null, messaggio, chiavePubblicaDa(chiavePubblica), firma);
    } catch {
      return false;
    }
  }
};

// packages/azione/src/banco-node.ts
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  lstatSync,
  statSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, normalize, relative, sep } from "node:path";
var COMANDO_SUITE_PREDEFINITO = "npx vitest run --reporter=json --outputFile={uscita} {file}";
function collegamento(percorso) {
  try {
    return lstatSync(percorso).isSymbolicLink();
  } catch {
    return false;
  }
}
function percorsoSicuro(radice, file, \u00E8Collegamento = collegamento) {
  if (isAbsolute(file)) throw new Error(`percorso assoluto non ammesso: ${file}`);
  const pieno = normalize(join(radice, file));
  const rel = relative(radice, pieno);
  if (rel === "" || rel.startsWith("..")) throw new Error(`percorso fuori dalla radice: ${file}`);
  const pezzi = rel.split(sep);
  if (pezzi.includes(".git")) throw new Error(`percorso dentro .git non ammesso: ${file}`);
  let cammino = radice;
  for (const pezzo of pezzi) {
    cammino = join(cammino, pezzo);
    if (\u00E8Collegamento(cammino)) throw new Error(`collegamento nel percorso, non ammesso: ${file}`);
  }
  return pieno;
}
function argomentiSuite(modello, uscita, soloFile) {
  const parole = modello.split(/\s+/).filter((p) => p !== "");
  return parole.flatMap((p) => {
    if (p === "{file}") return soloFile ?? [];
    return [p.replaceAll("{uscita}", uscita)];
  });
}
var AMBIENTE_AMMESSO = [
  /^(?:PATH|HOME|USER|SHELL|TMPDIR|TMP|TEMP|LANG|TZ|TERM)$/,
  /^LC_/,
  /^NODE_/,
  /^npm_config_/i
];
function ambienteDellaSuite(ambiente) {
  const fuori = { CI: "1" };
  for (const [nome, valore] of Object.entries(ambiente))
    if (valore !== void 0 && AMBIENTE_AMMESSO.some((re) => re.test(nome))) fuori[nome] = valore;
  return fuori;
}
function bancoNode(o) {
  const radice = realpathSync(normalize(o.radice));
  const modello = o.comandoSuite ?? COMANDO_SUITE_PREDEFINITO;
  const tempoMassimo = o.tempoMassimoMs ?? 20 * 60 * 1e3;
  const cartellaUscite = mkdtempSync(join(tmpdir(), "collaudo-azione-"));
  process.on("exit", () => rmSync(cartellaUscite, { recursive: true, force: true }));
  return {
    radice,
    // Solo un FILE ha un testo: una cartella allo stesso percorso è «non c'è», non un'eccezione.
    leggi: (file) => {
      const p = percorsoSicuro(radice, file);
      return existsSync(p) && statSync(p).isFile() ? readFileSync(p, "utf8") : null;
    },
    // La cartella della prova sigillata può non esserci più (la consegna l'ha tolta): si ricrea.
    scrivi: (file, testo2) => {
      const p = percorsoSicuro(radice, file);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, testo2, "utf8");
    },
    sha256Hex: (testo2) => crittografiaNode.sha256Hex(testo2),
    adesso: () => Date.now(),
    eseguiSuite: (soloFile) => {
      const uscita = join(
        cartellaUscite,
        `rapporto-${Date.now()}-${Math.random().toString(16).slice(2)}.json`
      );
      const [comando, ...args] = argomentiSuite(modello, uscita, soloFile);
      if (!comando) throw new Error("il comando della suite \xE8 vuoto");
      spawnSync(comando, args, {
        cwd: radice,
        stdio: "ignore",
        timeout: tempoMassimo,
        env: ambienteDellaSuite(process.env)
      });
      if (!existsSync(uscita)) return null;
      try {
        return JSON.parse(readFileSync(uscita, "utf8"));
      } catch {
        return null;
      }
    }
  };
}
function shaDi(radice, riferimento = "HEAD") {
  const r = spawnSync("git", ["rev-parse", riferimento], { cwd: radice, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git rev-parse ${riferimento}: ${(r.stderr ?? "").trim()}`);
  return r.stdout.trim();
}
function passaggioSuDisco(cartella, fileUscite) {
  const percorso = (nome) => join(cartella, `${nome}.json`);
  return {
    leggi(nome, limiteByte) {
      const p = percorso(nome);
      if (!existsSync(p)) return null;
      const testo2 = readFileSync(p, "utf8");
      if (Buffer.byteLength(testo2) > limiteByte) throw new Error(`${nome}.json supera ${limiteByte} byte`);
      try {
        return JSON.parse(testo2);
      } catch {
        throw new Error(`${nome}.json non \xE8 JSON`);
      }
    },
    scrivi(nome, valore) {
      mkdirSync(cartella, { recursive: true });
      writeFileSync(percorso(nome), JSON.stringify(valore), "utf8");
    },
    uscita(nome, valore) {
      if (fileUscite) appendFileSync(fileUscite, `${nome}=${valore}
`, "utf8");
    }
  };
}

// packages/azione/src/esegui.ts
var perch\u00E9 = (e) => e instanceof Error ? e.message : String(e);
function leggiSeSicuro(banco, file) {
  try {
    return banco.leggi(file);
  } catch {
    return null;
  }
}
function impronteDi(banco, file) {
  const impronte = {};
  for (const f of [...new Set(file)].sort()) {
    const testo2 = leggiSeSicuro(banco, f);
    if (testo2 !== null) impronte[f] = banco.sha256Hex(testo2);
  }
  return impronte;
}
function conToppe(banco, toppe, dentro) {
  const originali = /* @__PURE__ */ new Map();
  try {
    for (const t of toppe) {
      let prima;
      try {
        prima = banco.leggi(t.file);
      } catch (e) {
        return { applicata: false, nota: perch\u00E9(e) };
      }
      const dopo = prima === null ? null : applicaMutazione(prima, t);
      if (prima === null || dopo === null) return { applicata: false };
      if (!originali.has(t.file)) originali.set(t.file, prima);
      banco.scrivi(t.file, dopo);
    }
    return { applicata: true, valore: dentro() };
  } finally {
    for (const [file, testo2] of originali) banco.scrivi(file, testo2);
  }
}
function accorcia(x) {
  if (typeof x === "string") return x.length > LIMITI.stringa ? `${x.slice(0, LIMITI.stringa)}\u2026` : x;
  if (Array.isArray(x)) return x.map(accorcia);
  if (typeof x === "object" && x !== null)
    return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, accorcia(v)]));
  return x;
}
function corri(banco, corsa, impronta) {
  const eseguitaIl = banco.adesso();
  const r = conToppe(banco, corsa.toppe, () => {
    const rapporto2 = accorcia(corsa.soloFile ? banco.eseguiSuite(corsa.soloFile) : banco.eseguiSuite());
    return { rapporto: rapporto2, impronte: impronteDi(banco, impronta) };
  });
  if (!r.applicata)
    return { applicata: false, rapporto: null, eseguitaIl, nota: r.nota ?? "una toppa non si applica" };
  const { rapporto, impronte } = r.valore;
  if (rapporto === null || rapporto === void 0)
    return {
      applicata: true,
      rapporto: null,
      eseguitaIl,
      nota: "il runner non ha scritto un rapporto",
      impronte
    };
  if (JSON.stringify(rapporto).length > LIMITI.rapportoByte)
    return {
      applicata: true,
      rapporto: null,
      eseguitaIl,
      nota: `rapporto oltre ${LIMITI.rapportoByte} byte`,
      impronte
    };
  return { applicata: true, rapporto, eseguitaIl, impronte };
}
function eseguiOrdine(banco, ordine) {
  if (ordine.corse.length > LIMITI.corse)
    throw new Error(`l'ordine ha ${ordine.corse.length} corse, il tetto \xE8 ${LIMITI.corse}`);
  for (const [file, testo2] of Object.entries(ordine.scrivi))
    try {
      banco.scrivi(file, testo2);
    } catch {
    }
  const corse = ordine.corse.map((c) => ({ id: c.id, ...corri(banco, c, ordine.impronta) }));
  const letti = {};
  for (const f of ordine.leggi) letti[f] = leggiSeSicuro(banco, f);
  return { radice: banco.radice, corse, letti, impronte: impronteDi(banco, ordine.impronta) };
}

// packages/azione/src/servizio.ts
var AUDIENCE = "collaudo.io";
var PAZIENZA_MS = 6e4;
var dormi = (ms) => new Promise((r) => setTimeout(r, ms));
function conPazienza(rete, attendi = dormi) {
  return async (url, init) => {
    let atteso = 0;
    for (; ; ) {
      const risposta = await rete(url, init);
      if (risposta.status !== 429 && risposta.status !== 503) return risposta;
      const dopo = risposta.headers.get("retry-after");
      const ms = dopo !== null && /^\d+$/.test(dopo.trim()) ? Math.max(1e3, Number(dopo) * 1e3) : null;
      if (ms === null || atteso + ms > PAZIENZA_MS) return risposta;
      await risposta.body?.cancel();
      console.log(`collaudoio \xB7 il servizio dice di riprovare fra ${ms / 1e3} s: aspetto`);
      await attendi(ms);
      atteso += ms;
    }
  };
}
var indirizzo = (servizio, contratto, cosa) => `${servizio}/contratti/${encodeURIComponent(contratto)}/${cosa}`;
async function leggiOrdine(rete, servizio, contratto, token) {
  const dove = contratto ? indirizzo(servizio, contratto, "ordine") : `${servizio}/ordine`;
  const chi = contratto ?? "questo repository";
  const risposta = await rete(dove, {
    headers: { authorization: `Bearer ${token}`, accept: "application/json" }
  });
  if (!risposta.ok)
    throw new Error(
      `il servizio non d\xE0 l'ordine di ${chi}: HTTP ${risposta.status}${await motiviDi(risposta)}`
    );
  const testo2 = await risposta.text();
  if (testo2.length > LIMITI.ordineByte)
    throw new Error(`l'ordine supera ${LIMITI.ordineByte} byte: non lo eseguo`);
  let corpo;
  try {
    corpo = JSON.parse(testo2);
  } catch {
    throw new Error(`l'ordine di ${chi} non \xE8 JSON`);
  }
  const niente = corpo?.niente;
  if (typeof niente === "string") return { niente };
  if (!\u00E8Ordine(corpo)) throw new Error(`l'ordine di ${chi} non ha la forma attesa`);
  return { ordine: corpo };
}
async function tokenOidc(rete, ambiente, audience = AUDIENCE) {
  const url = ambiente.ACTIONS_ID_TOKEN_REQUEST_URL;
  const richiesta = ambiente.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !richiesta)
    throw new Error("manca il token OIDC: il job deve dichiarare `permissions: id-token: write`");
  const separatore = url.includes("?") ? "&" : "?";
  const risposta = await rete(`${url}${separatore}audience=${encodeURIComponent(audience)}`, {
    headers: { authorization: `Bearer ${richiesta}`, accept: "application/json; api-version=2.0" }
  });
  if (!risposta.ok) throw new Error(`GitHub non d\xE0 il token OIDC: HTTP ${risposta.status}`);
  const corpo = await risposta.json();
  if (typeof corpo.value !== "string" || corpo.value === "") throw new Error("il token OIDC \xE8 vuoto");
  return corpo.value;
}
async function spedisciRisultati(rete, servizio, token, r) {
  const risposta = await rete(indirizzo(servizio, r.contratto, "risultati"), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json"
    },
    body: JSON.stringify(r)
  });
  if (!risposta.ok)
    throw new Error(
      `il servizio ha rifiutato i risultati di ${r.contratto}: HTTP ${risposta.status}${await motiviDi(risposta)}`
    );
  return risposta.json();
}
async function motiviDi(risposta) {
  let corpo;
  try {
    corpo = await risposta.json();
  } catch {
    return "";
  }
  const c = corpo;
  const righe = [];
  if (typeof c.errore === "string") righe.push(c.errore);
  if (Array.isArray(c.motivi))
    for (const m of c.motivi)
      righe.push(
        typeof m === "string" ? m : `${String(m.codice)}: ${String(m.dettaglio)}`
      );
  return righe.map((r) => `
  \xB7 ${r}`).join("");
}

// packages/azione/src/main.ts
var FASI = ["ordine", "esegui", "spedisci"];
var input = (amb, nome) => {
  const v = amb[`INPUT_${nome.toUpperCase().replaceAll("-", "_")}`];
  return v === void 0 || v === "" ? void 0 : v;
};
var servizioDi = (amb) => (input(amb, "servizio") ?? "https://api.collaudo.io").replace(/\/+$/, "");
var LIMITE_FATTI = LIMITI.corse * LIMITI.rapportoByte + LIMITI.ordineByte;
function ordineLasciato(p) {
  const o = p.leggi("ordine", LIMITI.ordineByte);
  if (o === null) throw new Error("il job dell'ordine non ha lasciato nessun ordine");
  if (!\u00E8Ordine(o)) throw new Error("l'ordine lasciato non ha la forma attesa");
  return o;
}
async function faseOrdine(amb, rete, p) {
  const ordinato = await leggiOrdine(
    rete,
    servizioDi(amb),
    input(amb, "contratto"),
    await tokenOidc(rete, amb)
  );
  if ("niente" in ordinato) {
    console.log(`::notice title=Collaudo::${ordinato.niente}`);
    console.log(`collaudoio \xB7 niente da fare: ${ordinato.niente}`);
    p.uscita("ordine", "no");
    return;
  }
  p.scrivi("ordine", ordinato.ordine);
  p.uscita("ordine", "si");
  console.log(
    `collaudoio \xB7 ${ordinato.ordine.contratto} \xB7 ordine ricevuto: ${ordinato.ordine.corse.length} corse`
  );
}
function faseEsegui(amb, p, banco) {
  if (amb.ACTIONS_ID_TOKEN_REQUEST_URL || amb.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
    throw new Error(
      "il job che esegue il codice del cliente non deve avere `id-token: write`: il token lo coniano solo i job dell'ordine e della spedizione"
    );
  const ordine = ordineLasciato(p);
  const b = banco(amb.GITHUB_WORKSPACE ?? process.cwd());
  const commit = shaDi(b.radice);
  if (ordine.sha !== commit)
    throw new Error(`l'ordine vale sul commit ${ordine.sha}, il checkout \xE8 ${commit}`);
  p.scrivi("fatti", eseguiOrdine(b, ordine));
  console.log(
    `collaudoio \xB7 ${ordine.contratto} \xB7 ${commit.slice(0, 12)} \xB7 ${ordine.corse.length} corse eseguite`
  );
}
async function faseSpedisci(amb, rete, p) {
  const ordine = ordineLasciato(p);
  const fatti = p.leggi("fatti", LIMITE_FATTI);
  if (fatti === null) throw new Error("il job dell'esecuzione non ha lasciato i fatti");
  const usoAI = input(amb, "uso-ai");
  const risultati = {
    ordine: ordine.id,
    contratto: ordine.contratto,
    commit: ordine.sha,
    repository: amb.GITHUB_REPOSITORY ?? "",
    radice: fatti.radice,
    corse: fatti.corse,
    letti: fatti.letti,
    impronte: fatti.impronte,
    ...usoAI === void 0 ? {} : { dichiarazione: { usoAI: usoAI === "true" || usoAI === "s\xEC" } }
  };
  if (!\u00E8Risultati(risultati)) throw new Error("i fatti lasciati dall'esecuzione non hanno la forma attesa");
  const ricevuta = await spedisciRisultati(rete, servizioDi(amb), await tokenOidc(rete, amb), risultati);
  console.log(`collaudoio \xB7 ${ordine.contratto} \xB7 ${ordine.sha.slice(0, 12)} \xB7 risultati spediti`);
  console.log(JSON.stringify(ricevuta));
}
async function main(amb = process.env, reteNuda = fetch, attendi) {
  const rete = conPazienza(reteNuda, attendi);
  const fase = input(amb, "fase");
  if (!FASI.includes(fase))
    throw new Error(`fase sconosciuta: ${fase ?? "(nessuna)"}; attese: ${FASI.join(", ")}`);
  const p = passaggioSuDisco(
    input(amb, "cartella") ?? join2(amb.RUNNER_TEMP ?? tmpdir2(), "collaudo"),
    amb.GITHUB_OUTPUT
  );
  if (fase === "ordine") return faseOrdine(amb, rete, p);
  if (fase === "spedisci") return faseSpedisci(amb, rete, p);
  const comando = input(amb, "comando");
  faseEsegui(amb, p, (radice) => bancoNode({ radice, ...comando ? { comandoSuite: comando } : {} }));
}
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((e) => {
    console.error(`collaudoio \xB7 errore: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
export {
  FASI,
  faseEsegui,
  faseOrdine,
  faseSpedisci,
  main
};
