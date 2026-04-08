from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from supabase import create_client, Client
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.utils import ImageReader
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from functools import wraps
from datetime import datetime
import unicodedata
import re
import os
import io
import requests

# ======================================================
# CONFIGURACIÓN
# ======================================================

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
EMAIL_DOMAIN         = "sesna.internal"

supabase:       Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

STATIC_DIR      = app.static_folder
STORAGE_BUCKET  = "acuses"
FONDO_STORAGE   = "acuse.png"  # ruta del fondo dentro del bucket

# ======================================================
# UTILIDADES
# ======================================================

def limpiar(txt):
    if txt is None:
        return ""
    return txt.strip().replace("\r", "").replace('"', '').replace('\ufeff', '')

def normalizar_texto(txt):
    if not txt:
        return ""
    txt = limpiar(txt)
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", "_", txt).lower()

def usuario_a_email(usuario: str) -> str:
    return f"{usuario}@{EMAIL_DOMAIN}"

def get_db():
    """
    Cliente Supabase autenticado con el JWT del usuario activo.
    Refresca el token automáticamente para soportar sesiones largas.
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

def proceso_cerrado(db, estado):
    resp = db.table("estados_proceso").select("cerrado").eq("estado", estado).execute()
    return bool(resp.data and resp.data[0].get("cerrado"))

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return wrapper

# ======================================================
# AUTENTICACIÓN
# ======================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario  = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()

        if not usuario or not password:
            return render_template("login.html", error="Completa todos los campos")

        try:
            resp   = supabase.auth.sign_in_with_password({
                "email":    usuario_a_email(usuario),
                "password": password
            })
            estado = (resp.user.user_metadata or {}).get("estado", "")
            if not estado:
                return render_template("login.html",
                                       error="Usuario sin estado asignado. Contacta al administrador.")

            session["usuario"]       = usuario
            session["estado"]        = estado
            session["access_token"]  = resp.session.access_token
            session["refresh_token"] = resp.session.refresh_token
            return redirect(url_for("home"))

        except Exception:
            return render_template("login.html", error="Credenciales inválidas")

    return render_template("login.html")


@app.route("/logout")
def logout():
    try:
        supabase.auth.sign_out()
    except Exception:
        pass
    session.clear()
    return redirect(url_for("home"))

# ======================================================
# VISTAS
# ======================================================

@app.route("/")
def home():
    return render_template("index.html",
                           usuario=session.get("usuario"),
                           estado=session.get("estado"))

@app.route("/resultados")
def resultados():
    return render_template("resultados.html",
                           usuario=session.get("usuario"),
                           estado=session.get("estado"))

@app.route("/validar-instituciones")
@login_required
def validar_instituciones():
    return render_template("validar_instituciones.html",
                           usuario=session.get("usuario"),
                           estado=session.get("estado"))

@app.route("/validar-codigos")
@login_required
def validar_codigos():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("entes_confirmados").select("id") \
               .eq("estado", estado).eq("confirmado", True).limit(1).execute()
    if not resp.data:
        return redirect(url_for("validar_instituciones"))
    return render_template("validar_codigos.html",
                           usuario=session.get("usuario"),
                           estado=session.get("estado"))

# ======================================================
# API — DASHBOARD
# ======================================================

@app.route("/api/resultados")
def api_resultados():
    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    codigos = db.table("codigos_etica").select("estado, fecha_publicacion").execute().data or []
    entes   = db.table("entes_confirmados").select("estado").eq("confirmado", True).execute().data or []

    entes_por_estado   = {}
    codigos_por_estado = {}
    años = {}

    for e in entes:
        est = e["estado"]
        entes_por_estado[est] = entes_por_estado.get(est, 0) + 1

    for c in codigos:
        est   = c["estado"]
        fecha = c.get("fecha_publicacion") or ""
        codigos_por_estado[est] = codigos_por_estado.get(est, 0) + 1
        if fecha:
            año = str(fecha)[:4]
            años[año] = años.get(año, 0) + 1

    todos_estados  = set(codigos_por_estado) | set(entes_por_estado)
    años_ordenados = sorted(años.items())

    estados = sorted([
        {
            "entidad":       est,
            "instituciones": entes_por_estado.get(est, 0),
            "porcentaje":    round(codigos_por_estado.get(est, 0) / entes_por_estado[est] * 100, 2)
                             if entes_por_estado.get(est) else 0
        }
        for est in todos_estados
    ], key=lambda x: x["entidad"])

    return jsonify({
        "total_codigos": len(codigos),
        "años":          [a for a, _ in años_ordenados],
        "valores":       [b for _, b in años_ordenados],
        "mapa":          codigos_por_estado,
        "estados":       estados
    })

# ======================================================
# API — INSTITUCIONES
# ======================================================

@app.route("/instituciones-base")
@login_required
def instituciones_base():
    db     = get_db()
    estado = session["estado"]

    guardados = db.table("entes_confirmados").select("*").eq("estado", estado).execute().data
    if guardados:
        return jsonify({"fuente": "guardado", "data": guardados})

    base = db.table("instituciones").select("*").eq("entidad_nombre", estado).execute().data or []
    data = [{"id": r["id"], "nombre": r["nombre"],
             "poderGobierno": r["poder_gobierno"], "entidad.nombre": r["entidad_nombre"]}
            for r in base]
    return jsonify({"fuente": "original", "data": data})


@app.route("/guardar-validacion", methods=["POST"])
@login_required
def guardar_validacion():
    db     = get_db()
    estado = session["estado"]

    if proceso_cerrado(db, estado):
        return jsonify({"error": "Proceso cerrado"}), 403

    registros = []
    for fila in request.get_json().get("filas", []):
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
            reg["es_nueva"] = True
        registros.append(reg)

    db.table("entes_confirmados").upsert(registros, on_conflict="estado,nombre").execute()
    return jsonify({"status": "ok"})


@app.route("/hay-entes-confirmados")
@login_required
def hay_entes_confirmados():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("entes_confirmados").select("id") \
               .eq("estado", estado).eq("confirmado", True).limit(1).execute()
    return jsonify({"hay": bool(resp.data)})


@app.route("/entes-confirmados-nombres")
@login_required
def entes_confirmados_nombres():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("entes_confirmados").select("nombre") \
               .eq("estado", estado).eq("confirmado", True).execute()
    return jsonify([r["nombre"] for r in (resp.data or [])])


@app.route("/instituciones-confirmadas")
@login_required
def instituciones_confirmadas():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("entes_confirmados").select("*") \
               .eq("estado", estado).eq("confirmado", True).execute()
    data   = [{"nombre": r["nombre"], "poderGobierno": r.get("poder_gobierno")}
              for r in (resp.data or [])]
    return jsonify(data)

# ======================================================
# API — CÓDIGOS DE ÉTICA
# ======================================================

@app.route("/datos-codigos")
@login_required
def datos_codigos():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("codigos_etica").select("*").eq("estado", estado).execute()
    return jsonify({normalizar_texto(r["nombre"]): r for r in (resp.data or [])})


@app.route("/estatus-codigos")
@login_required
def estatus_codigos():
    db     = get_db()
    estado = session["estado"]
    resp   = db.table("codigos_etica").select("nombre").eq("estado", estado).execute()
    return jsonify([normalizar_texto(r["nombre"]) for r in (resp.data or [])])


@app.route("/guardar-validacion-codigos", methods=["POST"])
@login_required
def guardar_validacion_codigos():
    db     = get_db()
    estado = session["estado"]

    if proceso_cerrado(db, estado):
        return jsonify({"error": "Proceso cerrado"}), 403

    registros = []
    for fila in request.get_json():
        fecha = limpiar(fila.get("fecha_publicacion")) or None
        try:
            num = int(fila.get("num_instituciones") or 0)
        except (ValueError, TypeError):
            num = 0
        registros.append({
            "estado":              estado,
            "nombre":              limpiar(fila.get("nombre")),
            "cuenta_codigo":       limpiar(fila.get("cuenta_codigo")),
            "link":                limpiar(fila.get("link")),
            "fecha_publicacion":   fecha,
            "cumple_lineamientos": limpiar(fila.get("cumple_lineamientos")),
            "num_instituciones":   num,
        })

    db.table("codigos_etica").upsert(registros, on_conflict="estado,nombre").execute()
    return jsonify({"status": "ok"})

# ======================================================
# ENVÍO FINAL + PDF
# ======================================================

@app.route("/enviar-validacion", methods=["POST"])
@login_required
def enviar_validacion():
    db     = get_db()
    estado = session["estado"]

    entes   = db.table("entes_confirmados").select("nombre") \
                .eq("estado", estado).eq("confirmado", True).execute().data
    codigos = db.table("codigos_etica").select("nombre").eq("estado", estado).execute().data or []

    if not entes:
        return jsonify({"error": "No hay entes validados"}), 400

    instituciones_validadas = [r["nombre"] for r in codigos]

    db.table("estados_proceso").upsert({
        "estado":     estado,
        "cerrado":    True,
        "cerrado_en": datetime.now().isoformat()
    }).execute()

    # Leer imagen de fondo desde Supabase Storage
    url_fondo   = supabase.storage.from_(STORAGE_BUCKET).get_public_url(FONDO_STORAGE)
    resp_fondo  = requests.get(url_fondo)
    fondo_bytes = io.BytesIO(resp_fondo.content)

    # Generar PDF en memoria
    nombre_pdf = f"acuse_codigos_etica_{normalizar_texto(estado)}.pdf"
    buffer     = io.BytesIO()

    doc    = SimpleDocTemplate(buffer, pagesize=LETTER,
                               rightMargin=72, leftMargin=72,
                               topMargin=120, bottomMargin=72)
    styles = getSampleStyleSheet()
    estilo_titulo = ParagraphStyle("Titulo", parent=styles["Heading1"],
                                   fontSize=26, textColor=colors.HexColor("#A11C3A"),
                                   alignment=1, spaceAfter=30)
    elements = [
        Paragraph("ACUSE", estilo_titulo),
        Paragraph(f"<b>Estado:</b> {estado}", styles["Normal"]),
        Paragraph(f"<b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]),
        Spacer(1, 0.3 * inch),
        Paragraph(f"<b>Instituciones reportadas:</b> {len(entes)}", styles["Normal"]),
        Paragraph(f"<b>Códigos de Ética validados:</b> {len(instituciones_validadas)}", styles["Normal"]),
        Spacer(1, 0.4 * inch),
        Paragraph("<b>Instituciones con Código Validado:</b>", styles["Heading3"]),
        Spacer(1, 0.2 * inch),
    ]

    if instituciones_validadas:
        elements.append(ListFlowable(
            [ListItem(Paragraph(n, styles["Normal"])) for n in instituciones_validadas],
            bulletType="bullet"
        ))
    else:
        elements.append(Paragraph("No se registraron códigos validados.", styles["Normal"]))

    elements += [
        Spacer(1, 0.5 * inch),
        Paragraph("El proceso queda formalmente cerrado.", styles["Normal"])
    ]

    def dibujar_fondo(canvas, doc):
        w, h = LETTER
        canvas.drawImage(ImageReader(fondo_bytes), 0, 0,
                         width=w, height=h, preserveAspectRatio=True, mask="auto")

    doc.build(elements, onFirstPage=dibujar_fondo, onLaterPages=dibujar_fondo)

    # Subir PDF a Supabase Storage
    supabase_admin.storage.from_(STORAGE_BUCKET).upload(
        path=nombre_pdf,
        file=buffer.getvalue(),
        file_options={"content-type": "application/pdf", "upsert": "true"}
    )

    url_pdf = supabase_admin.storage.from_(STORAGE_BUCKET).get_public_url(nombre_pdf)
    return jsonify({"status": "ok", "pdf": url_pdf})

# ======================================================
# ARRANQUE
# ======================================================

if __name__ == "__main__":
    app.run(debug=True)