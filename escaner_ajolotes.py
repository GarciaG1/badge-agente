"""Escáner de ajolotes: escucha los "hello" del juego por el badge conectado por USB y avisa con un pitido
cuando oye el ajolote que buscas. Corre hasta que lo detengas con Ctrl+C y guarda todo en escaner_ajolotes.csv.

Uso:  python escaner_ajolotes.py COM15 Scout
"""
import csv, os, random, struct, sys, time
import serial

NAMES = ['Agente', 'Burbujas', 'Elote', 'Abanico', 'Finanzas', 'Feliz', 'Poncho', 'Arbitro', 'Scout', 'Sede', 'Vibras']
NEAR_DBM = -80  # a esta señal o más fuerte, el juego desbloquea (src/modules/badge/AxolotlGame.h)


def varint(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


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


def beep(near):
    try:
        import winsound
        for _ in range(3 if near else 1):
            winsound.Beep(1800 if near else 1000, 250)
            time.sleep(0.1)
    except Exception:
        print('\a', end='', flush=True)


def connect(port):
    s = serial.Serial(port, 115200, timeout=0.2)
    want_config = varint(3 << 3) + varint(random.getrandbits(31))
    s.write(b'\xc3' * 32)
    time.sleep(0.1)
    s.write(bytes([0x94, 0xc3, 0, len(want_config)]) + want_config)
    return s


def heartbeat(s):
    s.write(bytes([0x94, 0xc3, 0, 2]) + varint(7 << 3 | 2) + b'\x00')


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else 'COM15'
    target = sys.argv[2] if len(sys.argv) > 2 else 'Scout'
    if target not in NAMES:
        sys.exit(f'Ajolote desconocido: {target}. Opciones: {", ".join(NAMES)}')
    target_id = NAMES.index(target)
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'escaner_ajolotes.csv')
    new_log = not os.path.exists(log_path)
    log = open(log_path, 'a', newline='', encoding='utf-8')
    writer = csv.writer(log)
    if new_log:
        writer.writerow(['hora', 'badge', 'id', 'ajolote', 'rssi_dbm'])

    print(f'Buscando a {target} en {port}. Ctrl+C para salir. Registro: {log_path}\n', flush=True)
    names, last_alert = {}, {}
    while True:
        try:
            s = connect(port)
            buf, last_hb = bytearray(), time.time()
            while True:
                if time.time() - last_hb > 60:
                    heartbeat(s)
                    last_hb = time.time()
                buf += s.read(4096)
                i = 0
                while i + 4 <= len(buf):
                    if buf[i] != 0x94 or buf[i + 1] != 0xc3:
                        i += 1
                        continue
                    n = buf[i + 2] << 8 | buf[i + 3]
                    if n > 512:
                        i += 1
                        continue
                    if i + 4 + n > len(buf):
                        break
                    try:
                        handle(bytes(buf[i + 4:i + 4 + n]), names, last_alert, target_id, writer, log)
                    except (ValueError, IndexError):
                        pass
                    i += 4 + n
                del buf[:i]
        except serial.SerialException as e:
            print(f'{time.strftime("%H:%M:%S")}  Sin conexión con el badge ({e.__class__.__name__}). Reintento en 5 s…', flush=True)
            time.sleep(5)


def handle(msg, names, last_alert, target_id, writer, log):
    for f, v in fields(msg):
        if f == 4:  # NodeInfo de la configuración inicial: nombres
            d = dict(fields(v))
            if 2 in d:
                names[d.get(1, 0)] = dict(fields(d[2])).get(2, b'?').decode('utf-8', 'replace')
        elif f == 2:  # paquete recibido por radio
            d = dict(fields(v))
            frm, rssi = d.get(1, 0), d.get(12, 0)
            if rssi > 2 ** 31:
                rssi -= 2 ** 64
            data = dict(fields(d.get(4, b'')))
            if data.get(1) == 4 and 2 in data:
                names[frm] = dict(fields(data[2])).get(2, b'?').decode('utf-8', 'replace')
            if data.get(1) != 256:
                continue
            pl = data.get(2, b'')
            if len(pl) != 7 or pl[:3] != b'AJ\x02' or pl[4] >= len(NAMES):
                continue
            who, axo, now = names.get(frm, f'!{frm:08x}'), pl[4], time.strftime('%H:%M:%S')
            writer.writerow([now, who, f'!{frm:08x}', NAMES[axo], rssi])
            log.flush()
            if axo == target_id:
                near = rssi >= NEAR_DBM
                print(f'{now}  >>> {who} TRAE A {NAMES[axo].upper()} ({rssi} dBm) '
                      f'{"¡ESTÁS A RANGO!" if near else "acércate más"} <<<', flush=True)
                # Pitido como mucho cada 20 s por badge para no volverte loco
                if time.time() - last_alert.get(frm, 0) > 20:
                    last_alert[frm] = time.time()
                    beep(near)
            else:
                print(f'{now}  {who}: {NAMES[axo]} ({rssi} dBm)', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nEscáner detenido.')
