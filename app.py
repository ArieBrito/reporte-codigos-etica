from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)
import os
import io
import requests
import unicodedata
import re
from functools import wraps
from datetime import datetime

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    ListFlowable, ListItem
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

from supabase import create_client, Client

# --------------------------------------------------
# APP
# --------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# --------------------------------------------------
# SUPABASE
# --------------------------------------------------

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

supabase:       Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

STORAGE_BUCKET = "acuses"
FONDO_STORAGE  = "acuse.png"

# Dominio ficticio para construir emails a partir del nombre de usuario
EMAIL_DOMAIN = "sesna.internal"

def usuario_a_email(usuario: str) -> str:
    return f"{usuario}@{EMAIL_DOMAIN}"

STATIC_DIR = app.static_folder

# --------------------------------------------------
# UTILIDADES
# --------------------------------------------------

def limpiar(txt):
    if txt is None:
        return ""
    return txt.strip().replace("\r", "").replace('"', '').replace('\ufeff', '')

def normalizar_texto(txt):
    if not txt:
        return ""
    txt = limpiar(txt)
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode("ascii")
    txt = re.sub(r"\s+", "_", txt)
    return txt.lower()

def get_supabase_autenticado():
    """
    Devuelve un cliente Supabase con la sesión del usuario activo.
    Refresca el token automáticamente si está próximo a vencer,
    lo que permite sesiones de larga duración sin re-login.
    """
    access_token  = session.get("access_token")
    refresh_token = session.get("refresh_token")

    if not access_token:
        return None

    cliente = create_client(SUPABASE_URL, SUPABASE_KEY)

    try:
        resp = cliente.auth.set_session(access_token, refresh_token)
        if resp.session:
            session["access_token"]  = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token
    except Exception:
        pass

    return cliente



# --------------------------------------------------
# Resultados
# --------------------------------------------------
@app.route("/resultados")
def resultados():
    return render_template("resultados.html",
                           usuario=session.get("usuario"),
                           estado=session.get("estado"),
                           supabase_url=SUPABASE_URL,
                           supabase_key=SUPABASE_KEY)

@app.route("/api/resultados")
def api_resultados():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    codigos = db.table("codigos_etica").select("estado, fecha_publicacion, link, num_instituciones").execute().data or []
    entes   = db.table("entes_confirmados").select("estado").eq("confirmado", True).execute().data or []

    entes_por_estado   = {}
    codigos_por_estado = {}
    codigos_con_link   = {}
    num_obligadas      = {}
    años = {}

    for e in entes:
        est = e["estado"]
        entes_por_estado[est] = entes_por_estado.get(est, 0) + 1

    for c in codigos:
        est   = c["estado"]
        fecha = c.get("fecha_publicacion") or ""
        link  = c.get("link") or ""
        num   = c.get("num_instituciones") or 0

        codigos_por_estado[est] = codigos_por_estado.get(est, 0) + 1

        if link.strip():
            codigos_con_link[est] = codigos_con_link.get(est, 0) + 1

        try:
            num_obligadas[est] = num_obligadas.get(est, 0) + int(num)
        except (ValueError, TypeError):
            pass

        if fecha:
            año = str(fecha)[:4]
            años[año] = años.get(año, 0) + 1

    todos_estados  = set(codigos_por_estado) | set(entes_por_estado)
    años_ordenados = sorted(años.items())

    estados = sorted([
        {
            "entidad":          est,
            "instituciones":    entes_por_estado.get(est, 0),
            "codigos_con_link": codigos_con_link.get(est, 0),
            "num_obligadas":    num_obligadas.get(est, 0),
        }
        for est in todos_estados
    ], key=lambda x: x["entidad"])

    return jsonify({
        "total_codigos": len(codigos),
        "años":          [a for a, _ in años_ordenados],
        "valores":       [b for _, b in años_ordenados],
        "mapa":          codigos_con_link,
        "estados":       estados
    })
# --------------------------------------------------
# DECORADOR LOGIN
# --------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        if "usuario" not in session:
            return redirect(url_for("home"))

        return f(*args, **kwargs)

    return wrapper

# --------------------------------------------------
# LOGIN / LOGOUT
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()

        if not usuario or not password:
            return render_template("login.html", error="Completa todos los campos")

        email = usuario_a_email(usuario)

        try:
            # Supabase valida las credenciales y regresa un JWT
            resp = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            # Extraer el estado desde los metadatos del usuario
            user_metadata = resp.user.user_metadata or {}
            estado = user_metadata.get("estado", "")

            if not estado:
                return render_template(
                    "login.html",
                    error="Este usuario no tiene un estado asignado. Contacta al administrador."
                )

            # Guardar en session de Flask (igual que antes)
            session["usuario"] = usuario
            session["estado"] = estado
            session["access_token"]  = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token  # para sesiones largas

            return redirect(url_for("home"))

        except Exception as e:
            # Supabase lanza excepción si las credenciales son inválidas
            return render_template("login.html", error="Credenciales inválidas")

    return render_template("login.html")


@app.route("/logout")
def logout():

    # Cerrar sesión también en Supabase si hay token activo
    token = session.get("access_token")
    if token:
        try:
            supabase.auth.sign_out()
        except Exception:
            pass

    session.clear()

    return redirect(url_for("home"))

# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

# --------------------------------------------------
# VALIDACIÓN DE INSTITUCIONES
# --------------------------------------------------

@app.route("/validar-instituciones")
@login_required
def validar_instituciones():
    return render_template(
        "validar_instituciones.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )


@app.route("/instituciones-base")
@login_required
def instituciones_base():

    estado = session["estado"]
    db = get_supabase_autenticado()

    # ¿Ya hay entes guardados para este estado?
    resp_guardados = db.table("entes_confirmados") \
        .select("*") \
        .eq("estado", estado) \
        .execute()

    if resp_guardados.data:
        return jsonify({
            "fuente": "guardado",
            "data": resp_guardados.data
        })

    # Si no hay, traer el catálogo base filtrado por estado
    resp_base = db.table("instituciones") \
        .select("*") \
        .eq("entidad_nombre", estado) \
        .execute()

    # Mapear columnas al formato que espera el frontend
    data = [
        {
            "id":             r["id"],
            "nombre":         r["nombre"],
            "poderGobierno":  r["poder_gobierno"],
            "entidad.nombre": r["entidad_nombre"],
        }
        for r in (resp_base.data or [])
    ]

    return jsonify({"fuente": "original", "data": data})


@app.route("/guardar-validacion", methods=["POST"])
@login_required
def guardar_validacion():

    estado = session["estado"]
    db = get_supabase_autenticado()

    # Verificar si el proceso está cerrado
    resp_proceso = db.table("estados_proceso") \
        .select("cerrado") \
        .eq("estado", estado) \
        .execute()

    if resp_proceso.data and resp_proceso.data[0].get("cerrado"):
        return jsonify({"error": "Proceso cerrado"}), 403

    data = request.get_json()

    # El frontend envía { filas: [{id, nombre, poderGobierno}] }
    filas = data.get("filas", [])

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
            reg["es_nueva"] = False
        except (ValueError, TypeError):
            reg["es_nueva"] = True  # id tipo "nuevo_1234567"

        registros.append(reg)

    db.table("entes_confirmados") \
        .upsert(registros, on_conflict="estado,nombre") \
        .execute()

    return jsonify({"status": "ok"})


@app.route("/hay-entes-confirmados")
@login_required
def hay_entes_confirmados():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id") \
        .eq("estado", estado) \
        .eq("confirmado", True) \
        .limit(1) \
        .execute()

    return jsonify({"hay": bool(resp.data)})


@app.route("/entes-confirmados-nombres")
@login_required
def entes_confirmados_nombres():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("nombre") \
        .eq("estado", estado) \
        .eq("confirmado", True) \
        .execute()

    return jsonify([r["nombre"] for r in (resp.data or [])])


# --------------------------------------------------
# VALIDACIÓN DE CÓDIGOS
# --------------------------------------------------

@app.route("/validar-codigos")
@login_required
def validar_codigos():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("id") \
        .eq("estado", estado) \
        .eq("confirmado", True) \
        .limit(1) \
        .execute()

    if not resp.data:
        return redirect(url_for("validar_instituciones"))

    return render_template(
        "validar_codigos.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )

@app.route("/datos-codigos")
@login_required
def datos_codigos():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("codigos_etica") \
        .select("*") \
        .eq("estado", estado) \
        .execute()

    # Indexar por nombre normalizado para lookup en el frontend
    resultado = {}
    for r in (resp.data or []):
        clave = normalizar_texto(r["nombre"])
        resultado[clave] = r

    return jsonify(resultado)

@app.route("/estatus-codigos")
@login_required
def estatus_codigos():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("codigos_etica") \
        .select("nombre") \
        .eq("estado", estado) \
        .execute()

    return jsonify([
        normalizar_texto(r["nombre"])
        for r in (resp.data or [])
    ])


@app.route("/instituciones-confirmadas")
@login_required
def instituciones_confirmadas():

    estado = session["estado"]
    db = get_supabase_autenticado()

    resp = db.table("entes_confirmados") \
        .select("*") \
        .eq("estado", estado) \
        .eq("confirmado", True) \
        .execute()

    # Mapear al formato que espera el frontend
    data = [
        {"nombre": r["nombre"], "poderGobierno": r.get("poder_gobierno")}
        for r in (resp.data or [])
    ]

    return jsonify(data)


@app.route("/guardar-validacion-codigos", methods=["POST"])
@login_required
def guardar_validacion_codigos():

    estado = session["estado"]
    db = get_supabase_autenticado()

    # Verificar si el proceso está cerrado
    resp_proceso = db.table("estados_proceso") \
        .select("cerrado") \
        .eq("estado", estado) \
        .execute()

    if resp_proceso.data and resp_proceso.data[0].get("cerrado"):
        return jsonify({"error": "Proceso cerrado"}), 403

    data = request.get_json()

    registros = []
    for fila in data:
        fecha = limpiar(fila.get("fecha_publicacion")) or None
        num   = fila.get("num_instituciones")
        try:
            num = int(num) if num not in (None, "") else 0
        except (ValueError, TypeError):
            num = 0

        registros.append({
            "estado":               estado,
            "nombre":               limpiar(fila.get("nombre")),
            "cuenta_codigo":        limpiar(fila.get("cuenta_codigo")),
            "link":                 limpiar(fila.get("link")),
            "fecha_publicacion":    fecha,
            "cumple_lineamientos":  limpiar(fila.get("cumple_lineamientos")),
            "num_instituciones":    num,
        })

    # Upsert: clave única es (estado, nombre)
    db.table("codigos_etica") \
        .upsert(registros, on_conflict="estado,nombre") \
        .execute()

    return jsonify({"status": "ok"})

# --------------------------------------------------
# ENVÍO FINAL + PDF
# --------------------------------------------------

@app.route("/enviar-validacion", methods=["POST"])
@login_required
def enviar_validacion():

    estado = session["estado"]
    db = get_supabase_autenticado()

    # --------------------------------------------------
    # CONTEO DESDE SUPABASE
    # --------------------------------------------------
    resp_entes = db.table("entes_confirmados") \
        .select("nombre") \
        .eq("estado", estado) \
        .eq("confirmado", True) \
        .execute()

    resp_codigos = db.table("codigos_etica") \
        .select("nombre") \
        .eq("estado", estado) \
        .execute()

    if not resp_entes.data:
        return jsonify({"error": "No hay entes validados"}), 400

    total_instituciones = len(resp_entes.data)
    instituciones_validadas = [r["nombre"] for r in (resp_codigos.data or [])]
    total_codigos = len(instituciones_validadas)

    # --------------------------------------------------
    # MARCAR COMO CERRADO EN SUPABASE
    # --------------------------------------------------
    db.table("estados_proceso").upsert({
        "estado":     estado,
        "cerrado":    True,
        "cerrado_en": datetime.now().isoformat()
    }).execute()

    # --------------------------------------------------
    # CREAR PDF EN MEMORIA Y SUBIR A STORAGE
    # --------------------------------------------------
    url_fondo   = supabase.storage.from_(STORAGE_BUCKET).get_public_url(FONDO_STORAGE)
    resp_fondo  = requests.get(url_fondo)
    fondo_bytes = io.BytesIO(resp_fondo.content)

    nombre_pdf = f"acuse_codigos_etica_{normalizar_texto(estado)}.pdf"
    buffer     = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        rightMargin=72,
        leftMargin=72,
        topMargin=120,
        bottomMargin=72
    )

    elements = []
    styles = getSampleStyleSheet()

    estilo_titulo = ParagraphStyle(
        'Titulo',
        parent=styles['Heading1'],
        fontSize=26,
        textColor=colors.HexColor("#A11C3A"),
        alignment=1,  # Centrado
        spaceAfter=30
    )

    # -----------------------
    # CONTENIDO
    # -----------------------

    elements.append(Paragraph("ACUSE", estilo_titulo))
    elements.append(Paragraph(f"<b>Estado:</b> {estado}", styles["Normal"]))
    elements.append(Paragraph(
        f"<b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph(
        f"<b>Instituciones reportadas:</b> {total_instituciones}",
        styles["Normal"]
    ))

    elements.append(Paragraph(
        f"<b>Códigos de Ética validados:</b> {total_codigos}",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 0.4 * inch))

    elements.append(Paragraph(
        "<b>Instituciones con Código Validado:</b>",
        styles["Heading3"]
    ))

    elements.append(Spacer(1, 0.2 * inch))

    if instituciones_validadas:
        lista_items = [
            ListItem(Paragraph(nombre, styles["Normal"]))
            for nombre in instituciones_validadas
        ]

        elements.append(
            ListFlowable(
                lista_items,
                bulletType='bullet'
            )
        )
    else:
        elements.append(
            Paragraph("No se registraron códigos validados.",
                      styles["Normal"])
        )

    elements.append(Spacer(1, 0.5 * inch))

    elements.append(Paragraph(
        "El proceso queda formalmente cerrado.",
        styles["Normal"]
    ))

    # --------------------------------------------------
    # FUNCIÓN PARA DIBUJAR FONDO
    # --------------------------------------------------
    def dibujar_fondo(canvas, doc):
        width, height = LETTER
        fondo = ImageReader(fondo_bytes)
        canvas.drawImage(
            fondo,
            0,
            0,
            width=width,
            height=height,
            preserveAspectRatio=True,
            mask='auto'
        )

    # --------------------------------------------------
    # GENERAR DOCUMENTO
    # --------------------------------------------------
    doc.build(
        elements,
        onFirstPage=dibujar_fondo,
        onLaterPages=dibujar_fondo
    )

    # Subir a Supabase Storage
    supabase_admin.storage.from_(STORAGE_BUCKET).upload(
        path=nombre_pdf,
        file=buffer.getvalue(),
        file_options={"content-type": "application/pdf", "upsert": "true"}
    )

    url_pdf = supabase_admin.storage.from_(STORAGE_BUCKET).get_public_url(nombre_pdf)
    return jsonify({"status": "ok", "pdf": url_pdf})


@app.route("/proceso-cerrado")
@login_required
def proceso_cerrado_endpoint():
    db     = get_supabase_autenticado()
    estado = session["estado"]
    resp   = db.table("estados_proceso") \
               .select("cerrado") \
               .eq("estado", estado) \
               .execute()
    cerrado = bool(resp.data and resp.data[0].get("cerrado"))
    return jsonify({"cerrado": cerrado})

# --------------------------------------------------
# ARRANQUE
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)