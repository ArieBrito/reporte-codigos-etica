from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os, io, re, time, unicodedata, requests
from functools import wraps
from datetime import datetime

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.utils import ImageReader
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

from supabase import create_client, Client, ClientOptions
import httpx

# ==============================================================
# CONFIGURACIÓN DE LA APP
# ==============================================================

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# ==============================================================
# TIMEOUTS
# CONNECT_TIMEOUT : tiempo máximo para establecer la conexión TCP.
# READ_TIMEOUT    : tiempo máximo esperando la primera respuesta.
# Se aplican tanto a requests.get (imagen de fondo del PDF) como
# a los clientes Supabase (postgrest y storage).
# ==============================================================

CONNECT_TIMEOUT = 3.05   # segundos — margen sobre el RTT típico de 3 s
READ_TIMEOUT    = 10.0   # segundos — suficiente para queries normales

_HTTPX_TIMEOUT = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
_SB_OPTIONS    = ClientOptions(
    postgrest_client_timeout = _HTTPX_TIMEOUT,
    storage_client_timeout   = int(READ_TIMEOUT),
)

# ==============================================================
# CLIENTES SUPABASE
# Usamos dos clientes:
#   · supabase       → cliente anónimo / RLS activo (usuarios)
#   · supabase_admin → service role, sin RLS (operaciones internas)
# Ambos comparten los mismos timeouts definidos en _SB_OPTIONS.
# ==============================================================

SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

supabase:       Client = create_client(SUPABASE_URL, SUPABASE_KEY,         options=_SB_OPTIONS)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY, options=_SB_OPTIONS)

STORAGE_BUCKET = "acuses"
FONDO_STORAGE  = "acuse.png"   # imagen de fondo para el PDF

# ==============================================================
# CACHÉ EN MEMORIA PARA EL DASHBOARD
# Evita reconsultar Supabase en cada petición al endpoint
# /api/resultados; se invalida al guardar cualquier cambio.
# ==============================================================

_cache_resultados: dict = {"data": None, "ts": 0.0}
CACHE_TTL = 30  # segundos

def invalidar_cache():
    _cache_resultados["data"] = None
    _cache_resultados["ts"]   = 0.0

# ==============================================================
# CONSTANTES DE AUTENTICACIÓN
# Los usuarios se guardan en Supabase Auth con el patrón
# <usuario>@sesna.internal para no exponer un email real.
# ==============================================================

EMAIL_DOMAIN = "sesna.internal"

def usuario_a_email(usuario: str) -> str:
    return f"{usuario}@{EMAIL_DOMAIN}"

# ==============================================================
# UTILIDADES
# ==============================================================

def limpiar(txt):
    """Elimina espacios, retornos de carro y caracteres problemáticos."""
    if txt is None:
        return ""
    return txt.strip().replace("\r", "").replace('"', '').replace('\ufeff', '')

def normalizar_texto(txt):
    """Convierte texto a snake_case ASCII, útil como clave de indexación."""
    if not txt:
        return ""
    txt = limpiar(txt)
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode("ascii")
    txt = re.sub(r"\s+", "_", txt)
    return txt.lower()

_CAMPOS_SESION = ("usuario", "estado", "access_token", "refresh_token")

def _sesion_valida() -> bool:
    """Devuelve True solo si los cuatro campos de sesión están presentes."""
    return all(session.get(c) for c in _CAMPOS_SESION)

def _limpiar_sesion_y_redirigir():
    """Limpia la sesión parcial y redirige al login."""
    session.clear()
    return redirect(url_for("login"))

def get_supabase_autenticado():
    """
    Devuelve un cliente Supabase con la sesión del usuario activo.
    Refresca el token automáticamente si está próximo a vencer,
    lo que permite sesiones de larga duración sin re-login.
    Lanza RuntimeError si la sesión está incompleta (no debería ocurrir
    porque login_required ya la valida antes de llegar aquí).
    """
    if not _sesion_valida():
        raise RuntimeError("Sesión incompleta — acceso no autorizado")

    access_token  = session["access_token"]
    refresh_token = session["refresh_token"]

    cliente = create_client(SUPABASE_URL, SUPABASE_KEY, options=_SB_OPTIONS)

    try:
        resp = cliente.auth.set_session(access_token, refresh_token)
        if resp.session:
            session["access_token"]  = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token
    except Exception:
        pass

    return cliente

# ==============================================================
# DECORADOR DE AUTENTICACIÓN
# Exige los cuatro campos de sesión. Si alguno falta (sesión
# parcial o caducada) limpia la cookie y redirige a /login.
# ==============================================================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _sesion_valida():
            return _limpiar_sesion_y_redirigir()
        return f(*args, **kwargs)
    return wrapper

# ==============================================================
# AUTENTICACIÓN: LOGIN / LOGOUT
# ==============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario  = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()

        if not usuario or not password:
            return render_template("login.html", error="Completa todos los campos")

        try:
            resp = supabase.auth.sign_in_with_password({
                "email":    usuario_a_email(usuario),
                "password": password
            })

            # El estado del usuario se almacena en sus metadatos de Supabase Auth
            estado = (resp.user.user_metadata or {}).get("estado", "").strip()
            if not estado:
                return render_template(
                    "login.html",
                    error="Este usuario no tiene un estado asignado. Contacta al administrador."
                )

            # F2-08: verificar que el valor de estado exista en el catálogo
            # para detectar errores de aprovisionamiento antes de que rompan
            # consultas posteriores con pantallas vacías o 500.
            existe = supabase.table("instituciones") \
                .select("id") \
                .eq("entidad_nombre", estado) \
                .limit(1).execute()
            if not existe.data:
                return render_template(
                    "login.html",
                    error=(
                        f"El estado '{estado}' no coincide con ningún registro "
                        "en el catálogo. Contacta al administrador."
                    )
                )

            session["usuario"]       = usuario
            session["estado"]        = estado
            session["access_token"]  = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token

            return redirect(url_for("menu"))

        except Exception:
            return render_template("login.html", error="Credenciales inválidas")

    return render_template("login.html")


@app.route("/logout")
def logout():
    try:
        if session.get("access_token"):
            supabase.auth.sign_out()
    except Exception:
        pass

    session.clear()
    return redirect(url_for("home"))

# ==============================================================
# PÁGINAS PRINCIPALES
# ==============================================================

@app.route("/")
def home():
    return render_template(
        "index.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

@app.route("/resultados")
def resultados():
    """Vista pública del dashboard de resultados (no requiere login)."""
    return render_template(
        "resultados.html",
        usuario=session.get("usuario"),
        estado=session.get("estado"),
        supabase_url=SUPABASE_URL,
        supabase_key=SUPABASE_KEY
    )

@app.route("/menu")
@login_required
def menu():
    return render_template(
        "menu.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

# ==============================================================
# API PÚBLICA: DASHBOARD DE RESULTADOS
# Devuelve totales, series de años y detalle por estado.
# Los datos se cachean en memoria por CACHE_TTL segundos.
# ==============================================================

@app.route("/api/resultados")
def api_resultados():
    ahora = time.time()

    if _cache_resultados["data"] and (ahora - _cache_resultados["ts"] < CACHE_TTL):
        return jsonify(_cache_resultados["data"])

    db = create_client(SUPABASE_URL, SUPABASE_KEY, options=_SB_OPTIONS)

    # Las vistas SQL hacen el trabajo pesado de agregación
    resumen = db.table("vista_resultados").select("*").execute().data or []
    anios   = db.table("vista_anios").select("*").execute().data or []

    # El detalle es granular, se trae en crudo y se indexa en Python
    detalle = db.table("codigos_etica") \
        .select("estado, nombre, cuenta_codigo, link, fecha_publicacion") \
        .execute().data or []

    # Indexar detalle por estado para O(1) en el armado final
    detalle_map = {}
    for d in detalle:
        detalle_map.setdefault(d["estado"], []).append({
            "nombre": d["nombre"],
            "cuenta": d["cuenta_codigo"],
            "link":   d["link"],
            "fecha":  d["fecha_publicacion"]
        })

    estados = [
        {
            "entidad":          r["estado"],
            "instituciones":    r["instituciones"],
            "codigos_con_link": r["codigos_con_link"],
            "codigos_con_si":   r["codigos_con_si"],
            "num_obligadas":    r["num_obligadas"],
            "detalle": sorted(
                detalle_map.get(r["estado"], []),
                key=lambda x: x["nombre"]
            )
        }
        for r in resumen
    ]

    resultado = {
        "total_codigos": sum(r["total_codigos"] for r in resumen),
        "años":          [a["anio"]  for a in anios],
        "valores":       [a["total"] for a in anios],
        "mapa":          {r["estado"]: r["codigos_con_link"] for r in resumen},
        "estados":       estados
    }

    _cache_resultados["data"] = resultado
    _cache_resultados["ts"]   = ahora

    return jsonify(resultado)

# ==============================================================
# VALIDACIÓN DE INSTITUCIONES (ENTES)
# Flujo: el usuario revisa/edita el catálogo base de su estado
# y guarda los entes confirmados en `entes_confirmados`.
# ==============================================================

@app.route("/validar-instituciones")
@login_required
def validar_instituciones():
    return render_template(
        "validar_instituciones.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )


# /instituciones-base fue eliminado: su lógica vive en /bootstrap-instituciones.


@app.route("/guardar-validacion", methods=["POST"])
@login_required
def guardar_validacion():
    """
    Persiste los entes validados por el usuario.
    Los ids tipo 'nuevo_xxx' se marcan como `es_nueva=True`.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    if _proceso_cerrado(db, estado):
        return jsonify({"error": "Proceso cerrado"}), 403

    filas     = request.get_json().get("filas", [])
    registros = []

    for fila in filas:
        raw_id = fila.get("id")
        reg = {
            "estado":         estado,
            "nombre":         limpiar(fila.get("nombre", "")),
            "poder_gobierno": limpiar(fila.get("poderGobierno", "")),
            "confirmado":     True,
        }
        try:
            reg["institucion_id"] = int(raw_id)
            reg["es_nueva"]       = False
        except (ValueError, TypeError):
            reg["es_nueva"]       = True   # id generado en el frontend

        registros.append(reg)

    db.table("entes_confirmados") \
        .upsert(registros, on_conflict="estado,nombre").execute()

    invalidar_cache()
    return jsonify({"status": "ok"})


@app.route("/hay-entes-confirmados")
@login_required
def hay_entes_confirmados():
    """Indica si el estado ya tiene al menos un ente confirmado."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id").eq("estado", estado).eq("confirmado", True) \
        .limit(1).execute()

    return jsonify({"hay": bool(resp.data)})


@app.route("/entes-confirmados-nombres")
@login_required
def entes_confirmados_nombres():
    """Lista de nombres de entes confirmados para el estado activo."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("nombre").eq("estado", estado).eq("confirmado", True).execute()

    return jsonify([r["nombre"] for r in (resp.data or [])])

# ==============================================================
# VALIDACIÓN DE CÓDIGOS DE ÉTICA
# Flujo: el usuario llena los datos de cada código de ética
# por institución y los guarda en `codigos_etica`.
# Requiere que ya existan entes confirmados.
# ==============================================================

@app.route("/validar-codigos")
@login_required
def validar_codigos():
    """Redirige a entes si el estado aún no tiene instituciones confirmadas."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id").eq("estado", estado).eq("confirmado", True) \
        .limit(1).execute()

    if not resp.data:
        return redirect(url_for("validar_instituciones"))

    return render_template(
        "validar_codigos.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )


# /datos-codigos fue eliminado: su lógica vive en /bootstrap-codigos.


# /estatus-codigos fue eliminado: su lógica vive en /bootstrap-codigos.


# /instituciones-confirmadas fue eliminado: su lógica vive en /bootstrap-codigos.


@app.route("/guardar-validacion-codigos", methods=["POST"])
@login_required
def guardar_validacion_codigos():
    """
    Persiste los datos de códigos de ética.
    Upsert con clave (estado, nombre); campos opcionales se normalizan.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    if _proceso_cerrado(db, estado):
        return jsonify({"error": "Proceso cerrado"}), 403

    registros = []
    for fila in request.get_json():
        num = fila.get("num_instituciones")
        try:
            num = int(num) if num not in (None, "") else 0
        except (ValueError, TypeError):
            num = 0

        registros.append({
            "estado":              estado,
            "nombre":              limpiar(fila.get("nombre")),
            "cuenta_codigo":       limpiar(fila.get("cuenta_codigo")),
            "link":                limpiar(fila.get("link")),
            "fecha_publicacion":   limpiar(fila.get("fecha_publicacion")) or None,
            "cumple_lineamientos": limpiar(fila.get("cumple_lineamientos")),
            "num_instituciones":   num,
        })

    db.table("codigos_etica") \
        .upsert(registros, on_conflict="estado,nombre").execute()

    invalidar_cache()
    return jsonify({"status": "ok"})

# ==============================================================
# ENVÍO FINAL + GENERACIÓN DE PDF
# Cierra el proceso del estado y genera el acuse en PDF,
# que se sube a Supabase Storage y se devuelve como URL pública.
# ==============================================================

@app.route("/enviar-validacion", methods=["POST"])
@login_required
def enviar_validacion():
    estado = session["estado"]
    db     = get_supabase_autenticado()

    # ── F2-04: verificar cobertura completa ────────────────────
    # Traer todos los entes confirmados del estado.
    resp_entes = db.table("entes_confirmados") \
        .select("nombre").eq("estado", estado).eq("confirmado", True).execute()

    if not resp_entes.data:
        return jsonify({"error": "No hay entes validados"}), 400

    nombres_entes = {r["nombre"] for r in resp_entes.data}

    # Solo cuentan los registros donde el usuario explícitamente respondió
    # "Sí" — los demás (No / No se recibió información) no son "validados".
    resp_codigos = db.table("codigos_etica") \
        .select("nombre, cuenta_codigo") \
        .eq("estado", estado).execute()

    codigos_data       = resp_codigos.data or []
    nombres_revisados  = {r["nombre"] for r in codigos_data}
    instituciones_con_si = [
        r["nombre"] for r in codigos_data
        if (r.get("cuenta_codigo") or "").strip() == "Sí"
    ]

    # Bloquear envío si algún ente confirmado no tiene registro en codigos_etica.
    sin_revisar = nombres_entes - nombres_revisados
    if sin_revisar:
        return jsonify({
            "error": "Revisión incompleta",
            "sin_revisar": sorted(sin_revisar),
        }), 400

    total_instituciones = len(nombres_entes)
    total_con_si        = len(instituciones_con_si)

    # ── F2-05 paso 1: descargar imagen de fondo (con fallback local) ──
    # La imagen se obtiene de Supabase Storage; si falla por cualquier
    # razón (bucket ausente, red, etc.) se usa el archivo local como
    # respaldo para que el PDF sí pueda generarse.
    RUTA_FONDO_LOCAL = os.path.join(app.root_path, "static", "assets", FONDO_STORAGE)
    fondo_bytes = None

    try:
        url_fondo = supabase.storage.from_(STORAGE_BUCKET).get_public_url(FONDO_STORAGE)
        resp_img  = requests.get(url_fondo, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        resp_img.raise_for_status()
        fondo_bytes = io.BytesIO(resp_img.content)
    except Exception:
        if os.path.exists(RUTA_FONDO_LOCAL):
            with open(RUTA_FONDO_LOCAL, "rb") as f:
                fondo_bytes = io.BytesIO(f.read())
        # Si tampoco existe el fallback local, fondo_bytes queda None
        # y el PDF se genera sin imagen de fondo (mejor que fallar).

    # ── F2-05 paso 2: construir PDF con ReportLab ──────────────
    nombre_pdf = f"acuse_codigos_etica_{normalizar_texto(estado)}.pdf"
    buffer     = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=LETTER,
        rightMargin=72, leftMargin=72,
        topMargin=120, bottomMargin=72
    )

    styles        = getSampleStyleSheet()
    estilo_titulo = ParagraphStyle(
        "Titulo",
        parent=styles["Heading1"],
        fontSize=26,
        textColor=colors.HexColor("#A11C3A"),
        alignment=1,
        spaceAfter=30
    )

    elements = [
        Paragraph("ACUSE", estilo_titulo),
        Paragraph(f"<b>Estado:</b> {estado}",                                   styles["Normal"]),
        Paragraph(f"<b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}",  styles["Normal"]),
        Spacer(1, 0.3 * inch),
        Paragraph(f"<b>Instituciones confirmadas:</b> {total_instituciones}",    styles["Normal"]),
        Paragraph(f"<b>Instituciones con Código de Ética (Sí):</b> {total_con_si}", styles["Normal"]),
        Spacer(1, 0.4 * inch),
        Paragraph("<b>Instituciones con Código de Ética publicado:</b>",         styles["Heading3"]),
        Spacer(1, 0.2 * inch),
    ]

    if instituciones_con_si:
        elements.append(ListFlowable(
            [ListItem(Paragraph(n, styles["Normal"])) for n in sorted(instituciones_con_si)],
            bulletType="bullet"
        ))
    else:
        elements.append(Paragraph("Ninguna institución reportó contar con código.", styles["Normal"]))

    elements += [
        Spacer(1, 0.5 * inch),
        Paragraph("El proceso queda formalmente cerrado.", styles["Normal"])
    ]

    def dibujar_fondo(canvas, doc):
        """Dibuja la imagen de fondo si está disponible; si no, omite sin error."""
        if not fondo_bytes:
            return
        fondo_bytes.seek(0)
        w, h = LETTER
        canvas.drawImage(
            ImageReader(fondo_bytes), 0, 0,
            width=w, height=h,
            preserveAspectRatio=True, mask="auto"
        )

    doc.build(elements, onFirstPage=dibujar_fondo, onLaterPages=dibujar_fondo)

    # ── F2-05 paso 3: subir PDF a Supabase Storage ─────────────
    # Si la subida falla, el proceso NO se marca como cerrado
    # y se devuelve error para que el usuario pueda reintentar.
    try:
        supabase_admin.storage.from_(STORAGE_BUCKET).upload(
            path=nombre_pdf,
            file=buffer.getvalue(),
            file_options={"content-type": "application/pdf", "upsert": "true"}
        )
        url_pdf = supabase_admin.storage.from_(STORAGE_BUCKET).get_public_url(nombre_pdf)
    except Exception as e:
        return jsonify({"error": f"No se pudo subir el acuse: {e}"}), 502

    # ── F2-05 paso 4: cerrar proceso SOLO si el PDF está disponible ──
    db.table("estados_proceso").upsert({
        "estado":     estado,
        "cerrado":    True,
        "cerrado_en": datetime.now().isoformat()
    }).execute()

    invalidar_cache()
    return jsonify({"status": "ok", "pdf": url_pdf})

# ==============================================================
# ENDPOINTS BOOTSTRAP
# Reducen el número de peticiones al cargar cada vista:
# devuelven en una sola llamada todos los datos que la página
# necesita para inicializarse.
# ==============================================================

@app.route("/bootstrap-instituciones")
@login_required
def bootstrap_instituciones():
    """
    Payload inicial para la vista de validación de entes.
    Incluye: instituciones (guardadas u originales), nombres
    confirmados, estatus de códigos y si el proceso está cerrado.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    guardados = db.table("entes_confirmados") \
        .select("*").eq("estado", estado).execute().data

    if guardados:
        instituciones = {"fuente": "guardado", "data": guardados}
    else:
        base = db.table("instituciones") \
            .select("*").eq("entidad_nombre", estado).execute().data or []
        instituciones = {
            "fuente": "original",
            "data": [
                {
                    "id":             r["id"],
                    "nombre":         r["nombre"],
                    "poderGobierno":  r["poder_gobierno"],
                    "entidad.nombre": r["entidad_nombre"],
                }
                for r in base
            ]
        }

    confirmados = [r["nombre"] for r in (guardados or []) if r.get("confirmado")]

    resp_codigos = db.table("codigos_etica") \
        .select("nombre").eq("estado", estado).execute()
    estatus = [normalizar_texto(r["nombre"]) for r in (resp_codigos.data or [])]

    return jsonify({
        "instituciones": instituciones,
        "confirmados":   confirmados,
        "estatus":       estatus,
        "cerrado":       _proceso_cerrado(db, estado),
    })


@app.route("/bootstrap-codigos")
@login_required
def bootstrap_codigos():
    """
    Payload inicial para la vista de validación de códigos.
    Incluye: instituciones confirmadas, datos de códigos
    guardados, estatus y si el proceso está cerrado.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp_entes = db.table("entes_confirmados") \
        .select("nombre, poder_gobierno") \
        .eq("estado", estado).eq("confirmado", True).execute()
    instituciones = [
        {"nombre": r["nombre"], "poderGobierno": r.get("poder_gobierno")}
        for r in (resp_entes.data or [])
    ]

    resp_codigos = db.table("codigos_etica") \
        .select("*").eq("estado", estado).execute()

    datos   = {}
    estatus = []
    for r in (resp_codigos.data or []):
        clave = normalizar_texto(r["nombre"])
        datos[clave] = r
        estatus.append(clave)

    return jsonify({
        "instituciones": instituciones,
        "datos":         datos,
        "estatus":       estatus,
        "cerrado":       _proceso_cerrado(db, estado),
    })


@app.route("/proceso-cerrado")
@login_required
def proceso_cerrado_endpoint():
    """
    Consulta puntual sobre si el proceso del estado activo esta cerrado.
    Reutilizable desde cualquier vista (validar_instituciones, validar_codigos).
    Los bootstraps ya incluyen este dato; este endpoint sirve para re-verificar
    el estado en tiempo real sin recargar todo el bootstrap.
    """
    db     = get_supabase_autenticado()
    estado = session["estado"]
    return jsonify({"cerrado": _proceso_cerrado(db, estado)})

# ==============================================================
# HELPERS INTERNOS
# ==============================================================

def _proceso_cerrado(db, estado: str) -> bool:
    """
    Consulta la tabla `estados_proceso` y devuelve True si
    el proceso del estado dado está marcado como cerrado.
    Centraliza esta lógica para evitar duplicación.
    """
    resp = db.table("estados_proceso") \
        .select("cerrado").eq("estado", estado).execute()
    return bool(resp.data and resp.data[0].get("cerrado"))

# ==============================================================
# HEALTH CHECKS
# /healthz → liveness:  el proceso está corriendo
# /readyz  → readiness: el proceso puede atender tráfico
#            (verifica conexión a Supabase)
# ==============================================================

@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


@app.route("/readyz")
def readyz():
    try:
        create_client(SUPABASE_URL, SUPABASE_KEY, options=_SB_OPTIONS) \
            .table("instituciones").select("id").limit(1).execute()
        return jsonify({"status": "ok", "supabase": "reachable"}), 200
    except Exception as e:
        return jsonify({"status": "error", "supabase": str(e)}), 503


# ==============================================================
# ARRANQUE
# ==============================================================

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host  = os.environ.get("HOST", "0.0.0.0")
    port  = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=debug)