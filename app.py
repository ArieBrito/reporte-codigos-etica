from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
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
# Permite ñ, acentos, etc. en respuestas JSON sin escaparlos como \uXXXX
app.config['JSON_AS_ASCII'] = False

CONNECT_TIMEOUT = 3.05
READ_TIMEOUT    = 10.0

_HTTPX_TIMEOUT = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
_SB_OPTIONS    = ClientOptions(
    postgrest_client_timeout = _HTTPX_TIMEOUT,
    storage_client_timeout   = int(READ_TIMEOUT),
)

SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

supabase:       Client = create_client(SUPABASE_URL, SUPABASE_KEY,         options=_SB_OPTIONS)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY, options=_SB_OPTIONS)

STORAGE_BUCKET = "acuses"
FONDO_STORAGE  = "acuse.png"

_cache_resultados: dict = {"data": None, "ts": 0.0}
CACHE_TTL = 30

def invalidar_cache():
    _cache_resultados["data"] = None
    _cache_resultados["ts"]   = 0.0

EMAIL_DOMAIN = "sesna.internal"

def usuario_a_email(usuario: str) -> str:
    return f"{usuario}@{EMAIL_DOMAIN}"

# ==============================================================
# UTILIDADES
# ==============================================================

def limpiar(txt):
    """
    Limpia y normaliza texto para garantizar consistencia en BD.
    - Normaliza a NFC (forma canónica compuesta) para que 'é' sea
      siempre un solo code point, evitando duplicados invisibles
      cuando el upsert hace match por (estado, nombre).
    - Reemplaza espacios no-rompibles y otros whitespaces raros por espacio normal.
    - Colapsa múltiples espacios consecutivos en uno solo.
    - Elimina caracteres de control invisibles (BOM, zero-width, etc.).
    """
    if txt is None:
        return ""

    # 1. Asegurar str (por si llega como bytes)
    if isinstance(txt, bytes):
        txt = txt.decode("utf-8", errors="replace")

    # 2. Normalización Unicode a NFC — CRÍTICO para acentos y ñ
    txt = unicodedata.normalize("NFC", txt)

    # 3. Eliminar caracteres invisibles problemáticos
    #    \ufeff = BOM, \u200b-\u200d = zero-width, \u2060 = word joiner, \r = CR
    txt = re.sub(r"[\ufeff\u200b-\u200d\u2060\r]", "", txt)

    # 4. Reemplazar espacios "raros" por espacio normal
    #    \u00a0 = NBSP (típico al pegar de Word), \u2009/\u202f = thin spaces, \t = tab
    txt = re.sub(r"[\u00a0\u2009\u202f\t]", " ", txt)

    # 5. Quitar comillas dobles (compatibilidad con CSV)
    txt = txt.replace('"', '')

    # 6. Colapsar múltiples espacios en uno solo
    txt = re.sub(r"\s+", " ", txt)

    return txt.strip()

def normalizar_texto(txt):
    if not txt:
        return ""
    txt = limpiar(txt)
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode("ascii")
    txt = re.sub(r"\s+", "_", txt)
    return txt.lower()

_CAMPOS_SESION = ("usuario", "estado", "access_token", "refresh_token")

def _sesion_valida() -> bool:
    return all(session.get(c) for c in _CAMPOS_SESION)

def _limpiar_sesion_y_redirigir():
    session.clear()
    return redirect(url_for("login"))

def get_supabase_autenticado():
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

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _sesion_valida():
            return _limpiar_sesion_y_redirigir()
        return f(*args, **kwargs)
    return wrapper

# ==============================================================
# AUTENTICACIÓN
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

            estado = (resp.user.user_metadata or {}).get("estado", "").strip()
            if not estado:
                return render_template(
                    "login.html",
                    error="Este usuario no tiene un estado asignado. Contacta al administrador."
                )

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
# ==============================================================

@app.route("/api/resultados")
def api_resultados():
    ahora = time.time()

    if _cache_resultados["data"] and (ahora - _cache_resultados["ts"] < CACHE_TTL):
        return jsonify(_cache_resultados["data"])

    db = create_client(SUPABASE_URL, SUPABASE_KEY, options=_SB_OPTIONS)

    resumen = db.table("vista_resultados").select("*").execute().data or []
    anios   = db.table("vista_anios").select("*").execute().data or []

    detalle = db.table("codigos_etica") \
        .select("estado, nombre, cuenta_codigo, link, fecha_publicacion") \
        .execute().data or []

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
        "total_codigos": sum(r["codigos_con_si"] for r in resumen),
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
# ==============================================================

@app.route("/validar-instituciones")
@login_required
def validar_instituciones():
    return render_template(
        "validar_instituciones.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

@app.route("/descarga/instituciones")
@login_required
def descarga_instituciones():
    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("nombre, poder_gobierno, confirmado, verificado") \
        .eq("estado", estado) \
        .execute()

    if not resp.data:
        resp_base = db.table("instituciones") \
            .select("nombre, poder_gobierno") \
            .eq("entidad_nombre", estado) \
            .execute()
        filas_data = [
            {
                "nombre":         r.get("nombre", ""),
                "poder_gobierno": r.get("poder_gobierno", ""),
                "confirmado":     None,
                "verificado":     False,
            }
            for r in (resp_base.data or [])
        ]
        filename = "instituciones_catalogo.csv"
    else:
        filas_data = resp.data
        filename   = "instituciones_verificadas.csv"

    def generar():
        yield "\uFEFF"
        encabezado = ["Nombre", "Poder de Gobierno", "Confirmado", "Verificado"]
        yield ",".join(f'"{c}"' for c in encabezado) + "\n"
        for r in filas_data:
            confirmado = r.get("confirmado")
            verificado = r.get("verificado")
            fila = [
                r.get("nombre", ""),
                r.get("poder_gobierno", ""),
                "Sí" if confirmado is True else ("No" if confirmado is False else "Sin verificar"),
                "Sí" if verificado is True else "No",
            ]
            yield ",".join(f'"{str(c).replace(chr(34), chr(34)*2)}"' for c in fila) + "\n"

    return Response(
        generar(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route("/descarga/codigos")
@login_required
def descarga_codigos():
    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("codigos_etica") \
        .select("nombre, cuenta_codigo, link, fecha_publicacion, cumple_lineamientos, num_instituciones") \
        .eq("estado", estado) \
        .execute()

    if not resp.data:
        # Solo entes verificados como base
        resp_base = db.table("entes_confirmados") \
            .select("nombre") \
            .eq("estado", estado) \
            .eq("verificado", True) \
            .execute()
        filas_data = [
            {
                "nombre":              r.get("nombre", ""),
                "cuenta_codigo":       "",
                "link":                "",
                "fecha_publicacion":   "",
                "cumple_lineamientos": "",
                "num_instituciones":   "",
            }
            for r in (resp_base.data or [])
        ]
        filename = "codigos_etica_sin_datos.csv"
    else:
        filas_data = resp.data
        filename   = "codigos_etica_cotejo.csv"

    def generar():
        yield "\uFEFF"
        encabezado = ["Institución", "¿Cuenta con código?", "Liga",
                      "Fecha de publicación", "¿Cumple lineamientos?",
                      "Núm. instituciones obligadas"]
        yield ",".join(f'"{c}"' for c in encabezado) + "\n"
        for r in filas_data:
            fila = [
                r.get("nombre", ""),
                r.get("cuenta_codigo", ""),
                r.get("link", ""),
                r.get("fecha_publicacion", "") or "",
                r.get("cumple_lineamientos", ""),
                str(r.get("num_instituciones", "") or ""),
            ]
            yield ",".join(f'"{str(c).replace(chr(34), chr(34)*2)}"' for c in fila) + "\n"

    return Response(
        generar(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ==============================================================
# GUARDAR VALIDACIÓN DE ENTES
# Estrategia:
#   1) DELETE explícito para entes que el usuario marcó como eliminados
#      (incluye sus códigos_etica asociados para no dejar huérfanos).
#   2) UPDATE para registros existentes cuyo nombre cambió: el frontend
#      envía `nombreOriginal` y lo usamos como llave WHERE para renombrar
#      la fila en lugar de insertar un duplicado. También se renombra en
#      codigos_etica para mantener la referencia por nombre.
#   3) UPSERT por (estado, nombre) para todo lo demás (registros nuevos
#      o existentes sin cambio de nombre).
# ==============================================================

@app.route("/guardar-validacion", methods=["POST"])
@login_required
def guardar_validacion():
    estado = session["estado"]
    db     = get_supabase_autenticado()

    if _proceso_cerrado(db, estado):
        return jsonify({"error": "Proceso cerrado"}), 403

    payload    = request.get_json() or {}
    filas      = payload.get("filas", [])
    eliminados = payload.get("eliminados", [])

# ----------------------------------------------------------
    # 1. ELIMINACIONES
    # Recibimos los nombres marcados como eliminados en el frontend.
    # Borramos primero el código de ética asociado (si existe) y
    # luego el ente. Esto evita huérfanos en codigos_etica.
    #
    # Si CUALQUIER paso falla, abortamos y reportamos al frontend.
    # No seguimos como si nada — el usuario debe saber que su
    # eliminación no se aplicó.
    # ----------------------------------------------------------
    errores_eliminacion = []

    for nombre_elim in eliminados:
        nombre_limpio = limpiar(nombre_elim)
        if not nombre_limpio:
            continue

        # Paso 1a: borrar el código de ética asociado (si existe)
        try:
            db.table("codigos_etica") \
                .delete() \
                .eq("estado", estado) \
                .eq("nombre", nombre_limpio) \
                .execute()
        except Exception as e:
            print(f"[ERROR delete codigos_etica '{nombre_limpio}']: {e}")
            errores_eliminacion.append({
                "nombre": nombre_limpio,
                "etapa":  "codigos_etica",
                "error":  str(e),
            })
            # No intentamos borrar el ente: si no pudimos limpiar
            # el código, dejarías un código huérfano. Mejor abortar
            # esta eliminación y seguir con la siguiente.
            continue

        # Paso 1b: borrar el ente
        try:
            db.table("entes_confirmados") \
                .delete() \
                .eq("estado", estado) \
                .eq("nombre", nombre_limpio) \
                .execute()
        except Exception as e:
            print(f"[ERROR delete ente '{nombre_limpio}']: {e}")
            errores_eliminacion.append({
                "nombre": nombre_limpio,
                "etapa":  "entes_confirmados",
                "error":  str(e),
            })

    # Si hubo errores en eliminaciones, abortamos antes del upsert.
    # Esto previene un estado mixto donde unos cambios se aplicaron
    # y otros no.
    if errores_eliminacion:
        nombres_fallidos = ", ".join(e["nombre"] for e in errores_eliminacion)
        return jsonify({
            "error": (
                f"No se pudieron eliminar {len(errores_eliminacion)} "
                f"registro(s): {nombres_fallidos}. "
                "No se aplicó ningún otro cambio. Intenta de nuevo."
            ),
            "detalles": errores_eliminacion,
        }), 500

    # ----------------------------------------------------------
    # 2. CLASIFICAR FILAS: renombres vs upserts
    # Un renombre se detecta cuando:
    #   - el id NO empieza con "nuevo_" (es decir, ya existía en BD), Y
    #   - hay un nombreOriginal no vacío, Y
    #   - nombreOriginal != nombre_nuevo
    # Cualquier otro caso (nuevo, o existente sin cambio) va a upsert.
    # ----------------------------------------------------------
    para_upsert = []

    for fila in filas:
        raw_id          = fila.get("id")
        nombre_nuevo    = limpiar(fila.get("nombre", ""))
        nombre_original = limpiar(fila.get("nombreOriginal", ""))
        poder           = limpiar(fila.get("poderGobierno", ""))
        confirmado      = fila.get("confirmado", False)
        verificado      = fila.get("verificado", False)

        if not nombre_nuevo:
            continue

        es_nuevo = str(raw_id).startswith("nuevo_")

        # --- Caso renombre: UPDATE por nombre_original -----------------
        if (not es_nuevo) and nombre_original and nombre_original != nombre_nuevo:
            try:
                # Renombrar primero en codigos_etica para que la referencia
                # por nombre siga siendo consistente.
                # NOTA: si la unique key (estado, nombre) ya tiene un registro
                # con `nombre_nuevo` en codigos_etica, este UPDATE fallará por
                # conflicto. Es deseable: significa que el usuario está intentando
                # renombrar a un nombre que ya existe.
                db.table("codigos_etica") \
                    .update({"nombre": nombre_nuevo}) \
                    .eq("estado", estado) \
                    .eq("nombre", nombre_original) \
                    .execute()

                # Renombrar el ente (y de paso actualizar los demás campos).
                db.table("entes_confirmados") \
                    .update({
                        "nombre":         nombre_nuevo,
                        "poder_gobierno": poder,
                        "confirmado":     confirmado,
                        "verificado":     verificado,
                    }) \
                    .eq("estado", estado) \
                    .eq("nombre", nombre_original) \
                    .execute()
            except Exception as e:
                print(f"[ERROR rename '{nombre_original}' → '{nombre_nuevo}']: {e}")
                return jsonify({
                    "error": (
                        f"No se pudo renombrar '{nombre_original}' a "
                        f"'{nombre_nuevo}'. Posiblemente ya existe otro "
                        f"registro con ese nombre. Detalle: {str(e)}"
                    )
                }), 500
            continue

        # --- Caso normal: nuevo o sin cambio de nombre → upsert --------
        reg = {
            "estado":         estado,
            "nombre":         nombre_nuevo,
            "poder_gobierno": poder,
            "confirmado":     confirmado,
            "verificado":     verificado,
        }
        try:
            reg["institucion_id"] = int(raw_id)
            reg["es_nueva"]       = False
        except (ValueError, TypeError):
            reg["es_nueva"]       = True

        para_upsert.append(reg)

    # ----------------------------------------------------------
    # 3. UPSERT de los registros sin renombre
    # ----------------------------------------------------------
    if para_upsert:
        try:
            db.table("entes_confirmados") \
                .upsert(para_upsert, on_conflict="estado,nombre") \
                .execute()
        except Exception as e:
            print(f"[ERROR upsert]: {e}")
            return jsonify({"error": f"Error al guardar: {str(e)}"}), 500

    invalidar_cache()
    return jsonify({"status": "ok"})


@app.route("/hay-entes-confirmados")
@login_required
def hay_entes_confirmados():
    """Indica si el estado ya tiene al menos un ente verificado."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id").eq("estado", estado).eq("verificado", True) \
        .limit(1).execute()

    return jsonify({"hay": bool(resp.data)})

@app.route("/entes-confirmados-nombres")
@login_required
def entes_confirmados_nombres():
    """Lista de nombres de entes verificados para el estado activo."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("nombre").eq("estado", estado).eq("verificado", True).execute()

    return jsonify([r["nombre"] for r in (resp.data or [])])

# ==============================================================
# VALIDACIÓN DE CÓDIGOS DE ÉTICA
# ==============================================================

@app.route("/validar-codigos")
@login_required
def validar_codigos():
    """Redirige a entes si el estado aún no tiene entes verificados."""
    estado = session["estado"]
    db     = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id").eq("estado", estado).eq("verificado", True) \
        .limit(1).execute()

    if not resp.data:
        return redirect(url_for("validar_instituciones"))

    return render_template(
        "validar_codigos.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

@app.route("/guardar-validacion-codigos", methods=["POST"])
@login_required
def guardar_validacion_codigos():
    try:
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

        db.table("codigos_etica").delete().eq("estado", estado).execute()

        if registros:
            db.table("codigos_etica").insert(registros).execute()

        invalidar_cache()
        return jsonify({"status": "ok"})

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

# ==============================================================
# ENVÍO FINAL + GENERACIÓN DE PDF
# ==============================================================

@app.route("/enviar-validacion", methods=["POST"])
@login_required
def enviar_validacion():
    import hashlib
    import locale
    from reportlab.platypus import Table, TableStyle, HRFlowable, PageBreak, KeepTogether
    from reportlab.lib.enums import TA_CENTER

    estado = session["estado"]
    db     = get_supabase_autenticado()

    try:
        locale.setlocale(locale.LC_TIME, "es_MX.UTF-8")
    except locale.Error:
        try:
            locale.setlocale(locale.LC_TIME, "es_ES.UTF-8")
        except locale.Error:
            pass

    fecha_larga = datetime.now().strftime("%d/%m/%Y")

    # Solo entes verificados participan en el reporte
    resp_entes = db.table("entes_confirmados") \
        .select("nombre").eq("estado", estado).eq("verificado", True).execute()

    if not resp_entes.data:
        return jsonify({"error": "No hay entes verificados"}), 400

    nombres_entes = {r["nombre"] for r in resp_entes.data}

    resp_codigos_detalle = db.table("codigos_etica") \
        .select("nombre, cuenta_codigo, link, num_instituciones") \
        .eq("estado", estado) \
        .order("nombre") \
        .execute()

    codigos_detalle   = resp_codigos_detalle.data or []
    nombres_revisados = {r["nombre"] for r in codigos_detalle}
    total_con_si      = sum(
        1 for r in codigos_detalle
        if (r.get("cuenta_codigo") or "").strip() == "Sí"
    )

    if not codigos_detalle:
        return jsonify({"error": "Guarda la información antes de enviar"}), 400

    sin_revisar = nombres_entes - nombres_revisados
    if sin_revisar:
        faltantes = [
            {
                "estado":              estado,
                "nombre":              nombre,
                "cuenta_codigo":       "No se recibió información",
                "link":                "",
                "fecha_publicacion":   None,
                "cumple_lineamientos": "",
                "num_instituciones":   0,
            }
            for nombre in sin_revisar
        ]
        db.table("codigos_etica").upsert(faltantes, on_conflict="estado,nombre").execute()
        resp_codigos_detalle = db.table("codigos_etica") \
            .select("nombre, cuenta_codigo, link, num_instituciones") \
            .eq("estado", estado).order("nombre").execute()
        codigos_detalle = resp_codigos_detalle.data or []

    total_instituciones = len(nombres_entes)

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

    nombre_pdf = f"acuse_codigos_etica_{normalizar_texto(estado)}.pdf"
    buffer     = io.BytesIO()

    folio_raw = f"{estado}{datetime.now().isoformat()}"
    folio     = hashlib.sha256(folio_raw.encode()).hexdigest()[:8].upper()

    PAGE_W, PAGE_H = LETTER
    TOP_MARGIN    = 135
    BOTTOM_MARGIN = 85
    SIDE_MARGIN   = 72
    AREA_H        = PAGE_H - TOP_MARGIN - BOTTOM_MARGIN

    doc = SimpleDocTemplate(
        buffer, pagesize=LETTER,
        rightMargin=SIDE_MARGIN, leftMargin=SIDE_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN
    )

    styles = getSampleStyleSheet()
    VINO  = colors.HexColor("#A11C3A")
    GRIS  = colors.HexColor("#555555")
    CLARO = colors.HexColor("#F5F0F1")

    estilo_folio = ParagraphStyle("Folio", parent=styles["Normal"], fontSize=7, textColor=GRIS, alignment=2)
    estilo_intro = ParagraphStyle("Intro", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#1A1A1A"), leading=15, spaceBefore=4, spaceAfter=4, alignment=4)
    estilo_seccion = ParagraphStyle("Seccion", parent=styles["Normal"], fontSize=10, textColor=VINO, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=6)
    estilo_label = ParagraphStyle("Label", parent=styles["Normal"], fontSize=9, textColor=VINO, fontName="Helvetica-Bold")
    estilo_valor = ParagraphStyle("Valor", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#1A1A1A"))
    estilo_header = ParagraphStyle("Header", parent=styles["Normal"], fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", leading=12)
    estilo_fecha = ParagraphStyle("Fecha", parent=styles["Normal"], fontSize=10, textColor=GRIS, leading=15, alignment=2)
    estilo_inst = ParagraphStyle("Inst", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#1A1A1A"), leading=12)
    estilo_link = ParagraphStyle("Link", parent=styles["Normal"], fontSize=7, textColor=colors.HexColor("#1155CC"), leading=10)
    estilo_cierre = ParagraphStyle("Cierre", parent=styles["Normal"], fontSize=8, textColor=GRIS, fontName="Helvetica-Oblique", alignment=1)
    estilo_firma = ParagraphStyle("Firma", parent=styles["Normal"], fontSize=9, textColor=VINO, fontName="Helvetica-Bold", alignment=1, spaceBefore=6)

    def linea():
        from reportlab.platypus import HRFlowable
        return HRFlowable(width="100%", thickness=0.5, color=VINO, spaceAfter=8, spaceBefore=8)

    def tabla_datos(filas):
        from reportlab.platypus import Table, TableStyle
        data = [[Paragraph(e, estilo_label), Paragraph(v, estilo_valor)] for e, v in filas]
        t = Table(data, colWidths=[170, 300])
        t.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            *[("BACKGROUND",  (0, i), (-1, i), CLARO) for i in range(0, len(data), 2)],
        ]))
        return t

    def tabla_codigos(lista):
        from reportlab.platypus import Table, TableStyle
        encabezados = [
            Paragraph("Institución", estilo_header),
            Paragraph("¿Cuenta con código?", estilo_header),
            Paragraph("Enlace", estilo_header),
            Paragraph("Núm. instituciones", estilo_header),
        ]
        data = [encabezados]
        for inst in lista:
            link_txt = inst.get("link") or ""
            num      = inst.get("num_instituciones")
            num_str  = str(num) if num not in (None, "") else "—"
            data.append([
                Paragraph(inst.get("nombre", ""), estilo_inst),
                Paragraph(inst.get("cuenta_codigo") or "—", estilo_inst),
                Paragraph(f'<link href="{link_txt}">{link_txt}</link>' if link_txt else "— sin enlace", estilo_link),
                Paragraph(num_str, estilo_inst),
            ])
        t = Table(data, colWidths=[155, 75, 178, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), VINO),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            *[("BACKGROUND",  (0, i), (-1, i), CLARO) for i in range(1, len(data), 2)],
        ]))
        return t

    bloque_p1 = [
        Paragraph(f"Ciudad de México a {fecha_larga}", estilo_fecha),
        Spacer(1, 0.05 * inch),
        Paragraph(f"Folio: <b>{folio}</b>", estilo_folio),
        Spacer(1, 0.15 * inch),
        Paragraph(
            f"Se emite el presente acuse a la Secretaría Ejecutiva del Sistema Estatal "
            f"Anticorrupción de <b>{estado}</b>, en virtud de haber concluido la integración "
            f"de la información relativa al seguimiento de la emisión de Códigos de Ética, "
            f"el día <b>{datetime.now().strftime('%d/%m/%Y')}</b>.",
            estilo_intro
        ),
        Spacer(1, 0.08 * inch),
        Paragraph(
            "La Secretaría Ejecutiva del Sistema Nacional Anticorrupción agradece el compromiso "
            "y la valiosa participación de esta institución en favor del fortalecimiento de la "
            "coordinación entre instancias y del cumplimiento de los acuerdos del Sistema "
            "Nacional Anticorrupción.",
            estilo_intro
        ),
        Spacer(1, 0.15 * inch),
        linea(),
        Paragraph("RESUMEN DE VALIDACIÓN", estilo_seccion),
        tabla_datos([
            ("Instituciones verificadas:",               str(total_instituciones)),
            ("Instituciones con Código de Ética (Sí):", str(total_con_si)),
            ("Instituciones sin Código de Ética:",       str(total_instituciones - total_con_si)),
        ]),
        linea(),
        Spacer(1, 0.6 * inch),
        Paragraph("Secretaría Ejecutiva del Sistema Nacional Anticorrupción", estilo_firma),
    ]

    from reportlab.pdfgen.canvas import Canvas as RLCanvas
    tmp = io.BytesIO()
    tmp_canvas = RLCanvas(tmp, pagesize=LETTER)
    text_w = PAGE_W - 2 * SIDE_MARGIN
    total_h = 0
    for flowable in bloque_p1:
        w, h = flowable.wrap(text_w, AREA_H)
        total_h += h
    del tmp_canvas

    padding_top = max(0, (AREA_H - total_h) / 4)

    from reportlab.platypus import PageBreak
    elements = [Spacer(1, padding_top)] + bloque_p1 + [
        PageBreak(),
        Paragraph("CÓDIGOS DE ÉTICA VERIFICADOS", estilo_seccion),
        Spacer(1, 0.05 * inch),
    ]

    if codigos_detalle:
        elements.append(tabla_codigos(codigos_detalle))
    else:
        elements.append(Paragraph("No se registraron códigos de ética en este proceso.", estilo_inst))

    elements += [
        linea(),
        Spacer(1, 0.2 * inch),
        Paragraph("El proceso de validación queda formalmente cerrado.", estilo_cierre),
    ]

    def dibujar_fondo(canvas, doc):
        if not fondo_bytes:
            return
        fondo_bytes.seek(0)
        w, h = LETTER
        canvas.drawImage(ImageReader(fondo_bytes), 0, 0, width=w, height=h, preserveAspectRatio=True, mask="auto")

    doc.build(elements, onFirstPage=dibujar_fondo, onLaterPages=dibujar_fondo)

    try:
        supabase_admin.storage.from_(STORAGE_BUCKET).upload(
            path=nombre_pdf,
            file=buffer.getvalue(),
            file_options={"content-type": "application/pdf", "upsert": "true"}
        )
        url_pdf = supabase_admin.storage.from_(STORAGE_BUCKET).get_public_url(nombre_pdf)
    except Exception as e:
        return jsonify({"error": f"No se pudo subir el acuse: {e}"}), 502

    db.table("estados_proceso").upsert({
        "estado":     estado,
        "cerrado":    True,
        "cerrado_en": datetime.now().isoformat()
    }).execute()

    invalidar_cache()
    return jsonify({"status": "ok", "pdf": url_pdf})

# ==============================================================
# ENDPOINTS BOOTSTRAP
# ==============================================================

@app.route("/bootstrap-instituciones")
@login_required
def bootstrap_instituciones():
    """
    Payload inicial para la vista de validación de entes.
    Copia el catálogo base a entes_confirmados SOLO la primera vez
    (cuando entes_confirmados está vacío para el estado).
    Después de eso, lo que viva en entes_confirmados es la verdad,
    incluso si el usuario eliminó algunos del catálogo original.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    guardados = db.table("entes_confirmados") \
        .select("*").eq("estado", estado).execute().data

    if guardados:
        instituciones = {"fuente": "guardado", "data": guardados}
    else:
        # Primera vez: copiar catálogo base a entes_confirmados
        base = db.table("instituciones") \
            .select("*").eq("entidad_nombre", estado).execute().data or []

        registros_iniciales = [
            {
                "estado":         estado,
                "nombre":         limpiar(r["nombre"]),
                "poder_gobierno": r["poder_gobierno"],
                "confirmado":     False,
                "verificado":     False,
                "institucion_id": r["id"],
                "es_nueva":       False,
            }
            for r in base
        ]

        if registros_iniciales:
            db.table("entes_confirmados").insert(registros_iniciales).execute()
            guardados = db.table("entes_confirmados") \
                .select("*").eq("estado", estado).execute().data or []
        else:
            guardados = []

        instituciones = {
            "fuente": "original",
            "data":   guardados,
        }

    # Nombres de verificados (para la vista de códigos)
    verificados = [r["nombre"] for r in (guardados or []) if r.get("verificado")]

    resp_codigos = db.table("codigos_etica") \
        .select("nombre").eq("estado", estado).execute()
    estatus = [normalizar_texto(r["nombre"]) for r in (resp_codigos.data or [])]

    return jsonify({
        "instituciones": instituciones,
        "verificados":   verificados,
        "estatus":       estatus,
        "cerrado":       _proceso_cerrado(db, estado),
    })


@app.route("/bootstrap-codigos")
@login_required
def bootstrap_codigos():
    """
    Payload inicial para la vista de validación de códigos.
    Solo incluye entes con verificado = true.
    """
    estado = session["estado"]
    db     = get_supabase_autenticado()

    # Solo entes verificados como obligados a emitir código
    resp_entes = db.table("entes_confirmados") \
        .select("nombre, poder_gobierno") \
        .eq("estado", estado).eq("verificado", True).execute()
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
    db     = get_supabase_autenticado()
    estado = session["estado"]
    return jsonify({"cerrado": _proceso_cerrado(db, estado)})

# ==============================================================
# HELPERS INTERNOS
# ==============================================================

def _proceso_cerrado(db, estado: str) -> bool:
    resp = db.table("estados_proceso") \
        .select("cerrado").eq("estado", estado).execute()
    return bool(resp.data and resp.data[0].get("cerrado"))

# ==============================================================
# HEALTH CHECKS
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
# REPOSITORIO DE DOCUMENTOS DESCARGABLES
# ==============================================================
#
# Bucket de Supabase Storage donde viven los archivos del repositorio.
# Es PRIVADO por diseño: nunca se exponen URLs directas al cliente.
# Toda descarga pasa por /documentos/descargar/<slug>, que valida sesión
# y hace stream del binario al navegador.

REPOSITORIO_BUCKET = "repositorio"

# Catálogo de documentos disponibles.
#
# Para agregar un nuevo documento en el futuro basta con:
#   1. Subirlo al bucket `repositorio` en Supabase Storage.
#   2. Agregar una entrada nueva a esta lista.
#
# Campos:
#   slug             -> identificador URL-safe usado en la ruta de descarga.
#   nombre           -> texto visible en la tarjeta.
#   archivo          -> nombre exacto del objeto en el bucket.
#   nombre_descarga  -> nombre con el que se descargará en el navegador.
DOCUMENTOS_REPOSITORIO = [
    {
        "slug":            "lgra",
        "nombre":          "Ley General de Responsabilidades Administrativas",
        "archivo":         "LGRA.pdf",
        "nombre_descarga": "Ley_General_Responsabilidades_Administrativas.pdf",
    },
    {
        "slug":            "lineamientos-codigo-etica",
        "nombre":          "Acuerdo por el que se dan a conocer los lineamientos para la emisión del Código de Ética",
        "archivo":         "Lineamientos.pdf",
        "nombre_descarga": "Lineamientos_Codigo_Etica.pdf",
    },
    {
        "slug":            "manual-usuario",
        "nombre":          "Manual de Usuario",
        "archivo":         "usuario.pdf",
        "nombre_descarga": "Manual_de_Usuario.pdf",
    },
]

# Índice por slug para lookup O(1) en la ruta de descarga.
_DOCS_POR_SLUG = {d["slug"]: d for d in DOCUMENTOS_REPOSITORIO}


@app.route("/documentos")
@login_required
def documentos():
    """
    Vista del repositorio de documentos.
    Solo lista metadatos — los archivos NO se exponen aquí.
    """
    return render_template(
        "documentos.html",
        usuario     = session.get("usuario"),
        estado      = session.get("estado"),
        documentos  = DOCUMENTOS_REPOSITORIO,
    )


@app.route("/documentos/descargar/<slug>")
@login_required
def descargar_documento(slug):
    """
    Streamea un documento del bucket privado `repositorio` al usuario.
    - Valida sesión vía @login_required.
    - Valida que el slug exista en el catálogo (whitelist; previene
      path-traversal o intentos de descargar archivos arbitrarios).
    - Descarga el binario desde Supabase Storage con el SERVICE KEY
      (el bucket es privado, no se generan URLs públicas).
    """
    doc = _DOCS_POR_SLUG.get(slug)
    if not doc:
        return jsonify({"error": "Documento no encontrado"}), 404

    try:
        contenido = supabase_admin.storage \
            .from_(REPOSITORIO_BUCKET) \
            .download(doc["archivo"])
    except Exception as e:
        app.logger.exception("Error descargando %s: %s", doc["archivo"], e)
        return jsonify({"error": "No se pudo recuperar el documento"}), 502

    return Response(
        contenido,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{doc["nombre_descarga"]}"',
            "Cache-Control":       "private, no-store",
        },
    )


# ==============================================================
# ARRANQUE
# ==============================================================

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host  = os.environ.get("HOST", "0.0.0.0")
    port  = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=debug)