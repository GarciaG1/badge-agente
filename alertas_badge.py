"""Agente de alertas de ciberseguridad para el badge JSConf 2026.

Cada N minutos:
  1. Consulta tres fuentes públicas (sin API key): CISA KEV (vulnerabilidades explotadas activamente),
     NVD (CVE publicados en 24 h y cuántos son críticos) y Have I Been Pwned (última filtración).
  2. Un modelo local en Ollama lee esos datos y redacta un aviso en español: nivel (ROJO / AMARILLO / VERDE),
     titular, qué hacer y un resumen. Si Ollama no responde, un conjunto de reglas redacta el aviso.
  3. Dibuja el aviso en una imagen de 428x142 y la sube al badge por USB (XModem a /prefs/canvas.bin).
  4. Guarda alertas_estado.json y alertas_historial.jsonl, que lee la vista web alertas.html.

Uso:  python alertas_badge.py [--port COM15] [--every 30] [--model qwen2.5:1.5b] [--watch php,ivanti]
      [--once] [--no-upload] [--no-agent]
"""
import argparse, datetime, json, os, random, re, struct, sys, time, urllib.request
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
PNG = os.path.join(HERE, 'alertas_badge.png')
CACHE = os.path.join(HERE, 'alertas_cache.json')
STATE = os.path.join(HERE, 'alertas_estado.json')
HISTORY = os.path.join(HERE, 'alertas_historial.jsonl')
W, H = 428, 142
UA = {'User-Agent': 'badge-alertas/1.0 (JSConf MX 2026 badge)'}
OLLAMA = 'http://127.0.0.1:11434'
NEW_HOURS = 3
LEVELS = ('ROJO', 'AMARILLO', 'VERDE')
WATCH = []  # palabras a vigilar (--watch), en minúsculas


# ---------------------------------------------------------------- fuentes
def get_json(url, timeout=25):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return json.loads(r.read())


def strip_html(s):
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', s or '')).strip()


def fetch():
    """Devuelve un dict con todo lo que el agente y la imagen necesitan. Si una fuente falla, usa lo último guardado."""
    cached = {}
    if os.path.exists(CACHE):
        try:
            cached = json.load(open(CACHE, encoding='utf-8'))
        except (OSError, ValueError):
            cached = {}
    data = dict(cached)
    today = datetime.date.today()

    try:
        kev = get_json('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        vulns = sorted(kev['vulnerabilities'], key=lambda v: v['dateAdded'], reverse=True)
        week = [v for v in vulns if (today - datetime.date.fromisoformat(v['dateAdded'])).days < 7]
        data['kev'] = {
            'week': len(week),
            'week_ids': [v['cveID'] for v in week],
            'latest': [{
                'id': v['cveID'], 'what': f"{v['vendorProject']} {v['product']}", 'date': v['dateAdded'],
                'name': v.get('vulnerabilityName', ''), 'desc': v.get('shortDescription', '')[:260],
                'ransomware': v.get('knownRansomwareCampaignUse', 'Unknown'), 'due': v.get('dueDate', ''),
                'url': (re.findall(r'https?://\S+', v.get('notes', '')) or [''])[0].rstrip(';,'),
            } for v in vulns[:5]],
        }
    except Exception as e:  # noqa: BLE001 - cualquier fallo de red deja el valor anterior
        print('  KEV falló:', e)

    try:
        now = datetime.datetime.utcnow()
        fmt = lambda d: d.strftime('%Y-%m-%dT%H:%M:%S.000')
        base = f'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={fmt(now - datetime.timedelta(days=1))}&pubEndDate={fmt(now)}'
        total = get_json(base + '&resultsPerPage=1')['totalResults']
        time.sleep(7)  # sin API key, el NVD permite 5 peticiones cada 30 s
        crit = get_json(base + '&cvssV3Severity=CRITICAL&resultsPerPage=40')
        items = []
        for v in crit['vulnerabilities']:
            c = v['cve']
            desc = next((d['value'] for d in c.get('descriptions', []) if d['lang'] == 'en'), '')
            metrics = c.get('metrics', {})
            score = None
            for key_ in ('cvssMetricV31', 'cvssMetricV30'):
                if metrics.get(key_):
                    score = metrics[key_][0]['cvssData']['baseScore']
                    break
            items.append({'id': c['id'], 'desc': desc[:220], 'score': score})
        data['nvd'] = {'total': total, 'critical': crit['totalResults'], 'ids': [i['id'] for i in items], 'items': items[:8]}
    except Exception as e:  # noqa: BLE001
        print('  NVD falló:', e)

    try:
        b = get_json('https://haveibeenpwned.com/api/v3/latestbreach')
        data['breach'] = {'name': b['Name'], 'title': b.get('Title', b['Name']), 'domain': b.get('Domain', ''),
                          'count': b['PwnCount'], 'date': b['BreachDate'], 'added': b['AddedDate'][:10],
                          'desc': strip_html(b.get('Description', ''))[:300], 'classes': b.get('DataClasses', [])[:6]}
    except Exception as e:  # noqa: BLE001
        print('  HIBP falló:', e)

    # Novedades: cada id guarda cuándo se vio por primera vez. En la primera corrida nada cuenta como nuevo,
    # para no marcar todo; después, lo que aparece se etiqueta NUEVO durante NEW_HOURS horas.
    now_s = time.time()
    first_run = 'seen' not in cached
    seen = {k: v for k, v in cached.get('seen', {}).items() if now_s - v < 7 * 86400}
    ids = ([v['id'] for v in data.get('kev', {}).get('latest', [])] + data.get('kev', {}).get('week_ids', [])
           + data.get('nvd', {}).get('ids', []))
    if 'breach' in data:
        ids.append('breach:' + data['breach']['name'])
    # En la primera corrida se marcan como "vistos hace rato" (no como 0: la poda de 7 días los borraría y
    # volverían a aparecer como nuevos en la siguiente corrida).
    for i in ids:
        seen.setdefault(i, now_s - NEW_HOURS * 3600 - 1 if first_run else now_s)
    data['seen'] = seen
    data['updated'] = time.strftime('%H:%M')
    data['updated_iso'] = datetime.datetime.now().isoformat(timespec='seconds')
    json.dump(data, open(CACHE, 'w', encoding='utf-8'))
    return data


def is_new(d, i):
    return time.time() - d.get('seen', {}).get(i, 0) < NEW_HOURS * 3600


def watched(text):
    t = (text or '').lower()
    return any(w in t for w in WATCH)


def new_ids(d):
    kev, nvd, b = d.get('kev', {}), d.get('nvd', {}), d.get('breach')
    ids = [v['id'] for v in kev.get('latest', []) if is_new(d, v['id'])]
    ids += [i for i in nvd.get('ids', []) if is_new(d, i)]
    if b and is_new(d, 'breach:' + b['name']):
        ids.append('breach:' + b['name'])
    return ids


# ---------------------------------------------------------------- agente
SYSTEM = (
    'Eres un agente de ciberseguridad que redacta avisos breves en ESPAÑOL neutro para una pantalla pequeña. '
    'Recibes UNA vulnerabilidad que ya se está explotando (catálogo CISA KEV) y respondes SOLO con un JSON: '
    '{"titular": "...", "accion": "..."}. El titular (máximo 55 caracteres) dice qué pasa y en qué producto, '
    'por ejemplo "Explotación activa en Ivanti Connect Secure" o "Ransomware ataca FortiOS sin parchar". '
    'La acción (máximo 95 caracteres) empieza con un verbo en imperativo y dice qué hacer hoy con ese producto, '
    'por ejemplo "Parcha Connect Secure (CVE-2026-1234) o aísla el equipo de internet". Sin inglés, sin markdown, '
    'sin texto fuera del JSON.'
)
ENGLISH = re.compile(r'\b(the|to|for|and|with|update|upgrade|patch|version|security|vulnerability|improvements)\b', re.I)


def rules_brief(d):
    """Aviso por reglas, cuando Ollama no está disponible."""
    kev, nvd, b = d.get('kev', {}), d.get('nvd', {}), d.get('breach', {})
    today = datetime.date.today().isoformat()
    latest = kev.get('latest', [])
    top = latest[0] if latest else None
    added_today = [v for v in latest if v['date'] == today]
    ransom = [v for v in latest if v.get('ransomware') == 'Known']
    if ransom or added_today:
        nivel = 'ROJO'
    elif nvd.get('critical') or kev.get('week'):
        nivel = 'AMARILLO'
    else:
        nivel = 'VERDE'
    titular = f"Explotación activa: {top['what']}"[:55] if top else 'Sin novedades urgentes'
    accion = (f"Parchar {top['what']} ({top['id']}) hoy" if top else 'Revisar el panel cuando haya tiempo')[:95]
    resumen = [
        f"KEV: +{kev.get('week', 0)} explotadas esta semana" + (f", {len(added_today)} hoy" if added_today else ''),
        f"NVD: {nvd.get('critical', 0)} críticos de {nvd.get('total', 0)} CVE nuevos en 24 h",
        f"Filtración: {b.get('name', '?')} · {b.get('count', 0):,} cuentas" if b else 'Filtración: sin datos',
    ]
    return {'nivel': nivel, 'titular': titular, 'accion': accion, 'resumen': resumen,
            'destacado': top['id'] if top else '', 'agente': 'reglas'}


def agent_brief(d, model):
    """Las cifras y el nivel salen de las reglas (no se inventan); el modelo solo redacta titular y acción."""
    brief = rules_brief(d)
    latest = d.get('kev', {}).get('latest', [])
    if not latest:
        return brief
    top = latest[0]
    item = {k: top.get(k) for k in ('id', 'what', 'name', 'desc', 'ransomware', 'due', 'date')}
    item['agregada_hoy'] = top['date'] == datetime.date.today().isoformat()
    item['palabras_que_vigila_el_usuario'] = [w for w in WATCH if w in top['what'].lower()]
    body = json.dumps({
        'model': model, 'stream': False, 'format': 'json',
        'options': {'temperature': 0.1, 'num_ctx': 2048, 'num_predict': 200},
        'messages': [{'role': 'system', 'content': SYSTEM},
                     {'role': 'user', 'content': 'Vulnerabilidad:\n' + json.dumps(item, ensure_ascii=False)}],
    }).encode()
    req = urllib.request.Request(OLLAMA + '/api/chat', data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=240) as r:
        out = json.loads(json.loads(r.read())['message']['content'])
    # Se acepta solo si está en español y habla del producto; si no, se queda la redacción por reglas
    product_words = [w.lower() for w in re.findall(r'[A-Za-z]{4,}', top['what'])]
    titular = str(out.get('titular', '')).strip()
    accion = str(out.get('accion', '')).strip()
    if titular and not ENGLISH.search(titular) and any(w in titular.lower() for w in product_words):
        brief['titular'] = titular[:60]
    if accion and not ENGLISH.search(accion) and len(accion) > 15:
        brief['accion'] = accion[:100]
    brief['agente'] = model
    return brief


# ---------------------------------------------------------------- imagen
FONTS = os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'Fonts')
COLORS = {'ROJO': '#ff3b3b', 'AMARILLO': '#f6b818', 'VERDE': '#39ff14'}
BAND_TEXT = {'ROJO': 'ROJO · ACTÚA HOY', 'AMARILLO': 'AMARILLO · REVISA', 'VERDE': 'VERDE · SIN URGENCIAS'}


def font(name, size):
    for candidate in (name, 'arial.ttf'):
        try:
            return ImageFont.truetype(os.path.join(FONTS, candidate), size)
        except OSError:
            continue
    return ImageFont.load_default()


def wrap(dr, text, f, max_w, max_lines):
    lines, cur = [], ''
    for word in text.split():
        trial = (cur + ' ' + word).strip()
        if dr.textlength(trial, font=f) <= max_w:
            cur = trial
        else:
            lines.append(cur)
            cur = word
            if len(lines) == max_lines:
                break
    if len(lines) < max_lines:
        lines.append(cur)
    if len(lines) > max_lines or (len(lines) == max_lines and cur and lines[-1] != cur):
        lines = lines[:max_lines]
        last = lines[-1]
        while last and dr.textlength(last + '…', font=f) > max_w:
            last = last[:-1]
        lines[-1] = last + '…'
    return [l for l in lines if l]


def render(d, brief):
    bg, white, gray, gold = '#05070d', '#ffffff', '#8ea3c4', '#f6b818'
    level = brief['nivel']
    color = COLORS[level]
    img = Image.new('RGB', (W, H), bg)
    dr = ImageDraw.Draw(img)
    band_f, title_f, action_f, small_f, mono_f = (font('segoeuib.ttf', 12), font('segoeuib.ttf', 17),
                                                  font('segoeui.ttf', 12), font('segoeui.ttf', 10), font('consolab.ttf', 11))
    # Banda superior con el nivel
    dr.rectangle([(0, 0), (W, 21)], fill=color)
    dr.text((8, 3), '● ' + BAND_TEXT[level], font=band_f, fill=bg)
    right = f"act. {d.get('updated', '--:--')}"
    dr.text((W - 8 - dr.textlength(right, font=band_f), 3), right, font=band_f, fill=bg)
    n_new = len(new_ids(d))
    if n_new:
        msg = f"▲ {n_new} {'nueva' if n_new == 1 else 'nuevas'}"
        dr.text((W - 70 - dr.textlength(msg, font=band_f), 3), msg, font=band_f, fill=bg)

    # Titular (hasta 2 líneas) y acción (hasta 2 líneas)
    y = 27
    for line in wrap(dr, brief['titular'], title_f, W - 16, 2):
        dr.text((8, y), line, font=title_f, fill=white)
        y += 22
    y = max(y + 2, 53)
    for i, line in enumerate(wrap(dr, brief['accion'], action_f, W - 26, 2)):
        dr.text((8, y), ('→ ' if i == 0 else '   ') + line, font=action_f, fill=gold)
        y += 16
    # El espacio que sobre lo llenan las frases del resumen (NVD y filtración; KEV ya va en el titular)
    y = max(y + 2, 72)
    for line in brief.get('resumen', [])[1:3]:
        if y > 98:
            break
        dr.text((8, y), wrap(dr, line, small_f, W - 16, 1)[0], font=small_f, fill=gray)
        y += 13

    # Pie: cifras del día y el CVE destacado
    kev, nvd, b = d.get('kev', {}), d.get('nvd', {}), d.get('breach', {})
    dr.rectangle([(0, 111), (W, H)], fill='#0b1220')
    stats = f"KEV +{kev.get('week', '?')} sem · NVD {nvd.get('critical', '?')} críticos/24 h · filtración: {b.get('name', '?')}"
    dr.text((8, 114), wrap(dr, stats, small_f, W - 16, 1)[0], font=small_f, fill=gray)
    foot = brief.get('destacado') or ''
    hits = sorted({w for v in kev.get('latest', []) for w in WATCH if w in v['what'].lower()})
    if hits:
        foot += f"  ·  VIGILADO: {', '.join(hits)}"
    foot += f"  ·  agente: {brief.get('agente', '?')}"
    dr.text((8, 127), wrap(dr, foot, mono_f, W - 16, 1)[0], font=mono_f, fill=gold if brief.get('destacado') else gray)
    dr.line([(0, H - 2), (W, H - 2)], fill=color, width=2)
    return img


def rgb565_be(img):
    out = bytearray(W * H * 2)
    for i, (r, g, b) in enumerate(img.getdata()):
        v = (r >> 3) << 11 | (g >> 2) << 5 | b >> 3
        if v == 0xF81F:  # color transparente del badge
            v = 0xF81E
        out[2 * i], out[2 * i + 1] = v >> 8, v & 0xFF
    return bytes(out)


# ---------------------------------------------------------------- estado para la vista web
def save_state(d, brief):
    state = {
        'updated': d.get('updated_iso'), 'brief': brief, 'new_ids': new_ids(d), 'watch': WATCH,
        'kev': d.get('kev', {}), 'nvd': d.get('nvd', {}), 'breach': d.get('breach'),
    }
    tmp = STATE + '.tmp'
    json.dump(state, open(tmp, 'w', encoding='utf-8'), ensure_ascii=False)
    os.replace(tmp, STATE)
    entry = {'t': d.get('updated_iso'), 'nivel': brief['nivel'], 'titular': brief['titular'],
             'accion': brief['accion'], 'agente': brief.get('agente'), 'nuevas': len(new_ids(d))}
    lines = []
    if os.path.exists(HISTORY):
        lines = open(HISTORY, encoding='utf-8').read().splitlines()[-199:]
    lines.append(json.dumps(entry, ensure_ascii=False))
    open(HISTORY, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')


# ---------------------------------------------------------------- badge (protobuf + XModem, como en index.html)
def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def key(f, w): return varint((f << 3) | w)
def u(f, v): return key(f, 0) + varint(v)
def fx(f, v): return key(f, 5) + struct.pack('<I', v)
def b_(f, x): return key(f, 2) + varint(len(x)) + x


def fields(buf):
    i = 0

    def rv():
        nonlocal i
        r = s = 0
        while True:
            c = buf[i]
            i += 1
            r |= (c & 127) << s
            s += 7
            if not c & 128:
                return r
    while i < len(buf):
        k = rv()
        f, w = k >> 3, k & 7
        if w == 0:
            yield f, rv()
        elif w == 2:
            n = rv()
            yield f, buf[i:i + n]
            i += n
        elif w == 5:
            yield f, struct.unpack('<I', buf[i:i + 4])[0]
            i += 4
        elif w == 1:
            i += 8
        else:
            raise ValueError(w)


def crc16(data):
    crc = 0
    for x in data:
        crc = ((crc >> 8) | (crc << 8)) & 0xFFFF
        crc ^= x
        crc ^= (crc & 0xFF) >> 4
        crc ^= (crc << 12) & 0xFFFF
        crc ^= ((crc & 0xFF) << 5) & 0xFFFF
    return crc


class Badge:
    SOH, EOT, ACK, CAN = 1, 4, 6, 24

    def __init__(self, port):
        import serial
        self.s = serial.Serial(port, 115200, timeout=0.05, write_timeout=5)
        self.buf = bytearray()
        self.my = 0
        self.s.write(b'\xc3' * 32)
        time.sleep(0.1)
        self.frame(u(3, random.getrandbits(31)))  # want_config: así sabemos nuestro número de nodo
        self.pump(3, want_xmodem=False)
        self.s.read(1 << 20)
        self.buf.clear()

    def frame(self, p):
        self.s.write(bytes([0x94, 0xC3, len(p) >> 8, len(p) & 255]) + p)

    def pump(self, timeout, want_xmodem=True):
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.buf += self.s.read(4096)
            i = 0
            while i + 4 <= len(self.buf):
                if self.buf[i] != 0x94 or self.buf[i + 1] != 0xC3:
                    i += 1
                    continue
                n = self.buf[i + 2] << 8 | self.buf[i + 3]
                if n > 512:
                    i += 1
                    continue
                if i + 4 + n > len(self.buf):
                    break
                msg = bytes(self.buf[i + 4:i + 4 + n])
                i += 4 + n
                for f, v in fields(msg):
                    if f == 3:
                        self.my = dict(fields(v)).get(1, 0)
                    if f == 12 and want_xmodem:
                        d = dict(fields(v))
                        del self.buf[:i]
                        return d.get(1, 0), d.get(2, 0), d.get(4, b'')
            del self.buf[:i]
        return None

    def admin_input(self, code):
        pkt = fx(2, self.my) + b_(4, u(1, 6) + b_(2, b_(27, u(1, code)))) + fx(6, random.getrandbits(32))
        self.frame(b_(1, pkt))

    def xm_send(self, control, seq=0, data=None):
        m = u(1, control) + (u(2, seq) if seq else b'')
        if data is not None:
            c = crc16(data)
            m += (u(3, c) if c else b'') + b_(4, data)
        self.frame(b_(5, m))

    def upload_canvas(self, data):
        def step(c, seq=0, d=None):
            for _ in range(4):
                self.xm_send(c, seq, d)
                r = self.pump(3)
                if r and r[0] == self.ACK:
                    return
                if r and r[0] == self.CAN:
                    raise RuntimeError('el badge canceló la transferencia')
            raise RuntimeError(f'sin confirmación en el bloque {seq}')
        # La página Canvas no debe estar dibujándose mientras se reemplaza el archivo: pantalla apagada.
        self.admin_input(0)
        time.sleep(0.7)
        self.admin_input(24)
        time.sleep(0.5)
        try:
            step(self.SOH, 0, b'/prefs/canvas.bin\0')
            for k, off in enumerate(range(0, len(data), 128), start=1):
                step(self.SOH, k, data[off:off + 128])
            step(self.EOT)
            time.sleep(0.7)
        finally:
            self.admin_input(0)  # pantalla encendida otra vez, ya con la imagen nueva

    def close(self):
        self.s.close()


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', default='COM15')
    ap.add_argument('--every', type=int, default=30, help='minutos entre actualizaciones')
    ap.add_argument('--model', default='qwen2.5:1.5b', help='modelo de Ollama')
    ap.add_argument('--watch', default='', help='palabras a resaltar, separadas por coma (ej. "php,ivanti,fortinet")')
    ap.add_argument('--once', action='store_true', help='una sola actualización y salir')
    ap.add_argument('--no-upload', action='store_true', help='solo generar la imagen y el estado')
    ap.add_argument('--no-agent', action='store_true', help='no usar Ollama; aviso por reglas')
    a = ap.parse_args()
    WATCH.extend(w.strip().lower() for w in a.watch.split(',') if w.strip())
    while True:
        t0 = time.time()
        print(f'{time.strftime("%H:%M:%S")}  Consultando fuentes…', flush=True)
        data = fetch()
        brief = None
        if not a.no_agent:
            try:
                t1 = time.time()
                brief = agent_brief(data, a.model)
                print(f'  Agente ({a.model}) redactó el aviso en {time.time() - t1:.0f} s', flush=True)
            except Exception as e:  # noqa: BLE001 - Ollama apagado, modelo no descargado, JSON raro…
                print(f'  Agente no disponible ({e}); aviso por reglas', flush=True)
        if brief is None:
            brief = rules_brief(data)
        print(f'  [{brief["nivel"]}] {brief["titular"]}  →  {brief["accion"]}', flush=True)
        img = render(data, brief)
        img.save(PNG)
        img.resize((W * 3, H * 3), Image.NEAREST).save(PNG.replace('.png', '_3x.png'))
        save_state(data, brief)
        if not a.no_upload:
            # El USB del badge a veces no responde unos segundos (recién conectado o reiniciándose): 3 intentos.
            for attempt in range(1, 4):
                try:
                    badge = Badge(a.port)
                    t1 = time.time()
                    badge.upload_canvas(rgb565_be(img))
                    badge.close()
                    print(f'  Subida al badge en {time.time() - t1:.1f} s', flush=True)
                    break
                except Exception as e:  # noqa: BLE001 - puerto ocupado, badge desconectado, etc.
                    print(f'  No se pudo subir al badge (intento {attempt}/3): {e}', flush=True)
                    if attempt < 3:
                        time.sleep(20)
        if a.once:
            break
        wait = max(60, a.every * 60 - (time.time() - t0))
        print(f'  Próxima actualización en {wait / 60:.0f} min (Ctrl+C para salir)', flush=True)
        time.sleep(wait)


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # consolas de Windows sin UTF-8
        main()
    except KeyboardInterrupt:
        print('\nDetenido.')
