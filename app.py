from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)
import csv
import os
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

# --------------------------------------------------
# APP
# --------------------------------------------------

app = Flask(__name__)
app.secret_key = "clave_super_secreta_sna"

BASE_DIR = os.getcwd()
STATIC_DIR = app.static_folder

ESTADOS_DIR = os.path.join(STATIC_DIR, "estados")
os.makedirs(ESTADOS_DIR, exist_ok=True)

RUTA_FONDO = os.path.join(
    STATIC_DIR,
    "assets",
    "acuse",
    "acuse.png"
)

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

def carpeta_estado(estado):
    carpeta = normalizar_texto(estado)
    ruta = os.path.join(ESTADOS_DIR, carpeta)
    os.makedirs(ruta, exist_ok=True)
    return ruta

def archivo_entes_estado(estado):
    return os.path.join(carpeta_estado(estado), "entes.csv")

def archivo_codigos_estado(estado):
    return os.path.join(carpeta_estado(estado), "codigos.csv")

def archivo_cierre_estado(estado):
    return os.path.join(carpeta_estado(estado), "cerrado.flag")

# --------------------------------------------------
# USUARIOS
# --------------------------------------------------

USUARIOS = {
    "user_ags": {"password": "a", "estado": "Aguascalientes"},
    "user_bc": {"password": "53301t1UM4q8", "estado": "Baja California"},
    "user_bcs": {"password": "cX96VSmjy3kZ", "estado": "Baja California Sur"},
    "user_cdmx": {"password": "64Oydlt7bxwl", "estado": "Ciudad de México"},
    "user_mex": {"password": "56RnYLD1Xb7C", "estado": "Estado de México"},
}

# --------------------------------------------------
# Resultados
# --------------------------------------------------
@app.route("/resultados")
def resultados():
    return render_template("resultados.html")

@app.route("/api/resultados")
def api_resultados():

    estados = []
    codigos_por_estado = {}
    total_codigos = 0
    años = {}

    for carpeta in os.listdir(ESTADOS_DIR):

        ruta_codigos = os.path.join(ESTADOS_DIR, carpeta, "codigos.csv")
        ruta_entes = os.path.join(ESTADOS_DIR, carpeta, "entes.csv")

        if not os.path.exists(ruta_codigos):
            continue

        estado_nombre = carpeta.replace("_", " ").title()

        with open(ruta_codigos, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            lista = list(reader)

        total_estado = len(lista)
        codigos_por_estado[estado_nombre] = total_estado
        total_codigos += total_estado

        for r in lista:
            fecha = r.get("fecha_publicacion", "")
            if fecha:
                año = fecha[:4]
                años[año] = años.get(año, 0) + 1

        total_instituciones = 0
        if os.path.exists(ruta_entes):
            with open(ruta_entes) as f:
                total_instituciones = sum(1 for _ in f) - 1

        porcentaje = 0
        if total_instituciones > 0:
            porcentaje = round((total_estado / total_instituciones) * 100, 2)

        estados.append({
            "entidad": estado_nombre,
            "instituciones": total_instituciones,
            "porcentaje": porcentaje
        })

    años_ordenados = sorted(años.items())

    return jsonify({
        "total_codigos": total_codigos,
        "años": [a for a,b in años_ordenados],
        "valores": [b for a,b in años_ordenados],
        "mapa": codigos_por_estado,
        "estados": estados
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

        user = request.form.get("usuario")
        password = request.form.get("password")

        if user in USUARIOS and USUARIOS[user]["password"] == password:

            session["usuario"] = user
            session["estado"] = USUARIOS[user]["estado"]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Credenciales inválidas"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

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
    ruta_guardada = archivo_entes_estado(estado)

    if os.path.exists(ruta_guardada):

        with open(ruta_guardada, newline="", encoding="utf-8") as f:

            return jsonify({
                "fuente": "guardado",
                "data": list(csv.DictReader(f))
            })

    ruta_original = os.path.join(STATIC_DIR, "OICs.csv")

    with open(ruta_original, newline="", encoding="utf-8") as f:
        filas = list(csv.DictReader(f))

    filtradas = [
        fila for fila in filas
        if limpiar(fila.get("entidad.nombre")) == estado
    ]

    return jsonify({
        "fuente": "original",
        "data": filtradas
    })


@app.route("/guardar-validacion", methods=["POST"])
@login_required
def guardar_validacion():

    if os.path.exists(archivo_cierre_estado(session["estado"])):
        return jsonify({"error": "Proceso cerrado"}), 403

    data = request.get_json()

    ruta = archivo_entes_estado(session["estado"])

    with open(ruta, "w", newline="", encoding="utf-8") as f:

        writer = csv.writer(f, quoting=csv.QUOTE_ALL)

        writer.writerow(data["encabezados"])
        writer.writerows(data["filas"])

    return jsonify({"status": "ok"})


@app.route("/hay-entes-confirmados")
@login_required
def hay_entes_confirmados():

    ruta = archivo_entes_estado(session["estado"])

    if not os.path.exists(ruta):
        return jsonify({"hay": False})

    with open(ruta) as f:

        return jsonify({
            "hay": sum(1 for _ in f) > 1
        })


@app.route("/entes-confirmados-nombres")
@login_required
def entes_confirmados_nombres():

    ruta = archivo_entes_estado(session["estado"])

    if not os.path.exists(ruta):
        return jsonify([])

    with open(ruta, newline="", encoding="utf-8") as f:

        reader = csv.DictReader(f)

        return jsonify([
            limpiar(r["nombre"])
            for r in reader
        ])

# --------------------------------------------------
# VALIDACIÓN DE CÓDIGOS
# --------------------------------------------------

@app.route("/validar-codigos")
@login_required
def validar_codigos():

    ruta = archivo_entes_estado(session["estado"])

    if not os.path.exists(ruta):
        return redirect(url_for("validar_instituciones"))

    return render_template(
        "validar_codigos.html",
        usuario=session.get("usuario"),
        estado=session.get("estado")
    )


@app.route("/estatus-codigos")
@login_required
def estatus_codigos():

    ruta = archivo_codigos_estado(session["estado"])

    if not os.path.exists(ruta):
        return jsonify([])

    with open(ruta, newline="", encoding="utf-8") as f:

        reader = csv.DictReader(f)

        return jsonify([
            normalizar_texto(r["nombre"])
            for r in reader
        ])


@app.route("/instituciones-confirmadas")
@login_required
def instituciones_confirmadas():

    ruta = archivo_entes_estado(session["estado"])

    if not os.path.exists(ruta):
        return jsonify([])

    with open(ruta, newline="", encoding="utf-8") as f:

        return jsonify(list(csv.DictReader(f)))


@app.route("/guardar-validacion-codigos", methods=["POST"])
@login_required
def guardar_validacion_codigos():

    if os.path.exists(archivo_cierre_estado(session["estado"])):
        return jsonify({"error": "Proceso cerrado"}), 403

    data = request.get_json()

    ruta = archivo_codigos_estado(session["estado"])

    encabezados = [
        "nombre",
        "cuenta_codigo",
        "link",
        "fecha_publicacion",
        "cumple_lineamientos",
        "num_instituciones"
    ]

    registros = {}

    if os.path.exists(ruta):

        with open(ruta, newline="", encoding="utf-8") as f:

            reader = csv.DictReader(f)

            for r in reader:

                registros[normalizar_texto(r["nombre"])] = r

    for fila in data:

        clave = normalizar_texto(fila.get("nombre"))

        registros[clave] = {
            "nombre": limpiar(fila.get("nombre")),
            "cuenta_codigo": limpiar(fila.get("cuenta_codigo")),
            "link": limpiar(fila.get("link")),
            "fecha_publicacion": limpiar(fila.get("fecha_publicacion")),
            "cumple_lineamientos": limpiar(fila.get("cumple_lineamientos")),
            "num_instituciones": limpiar(fila.get("num_instituciones")),
        }

    with open(ruta, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=encabezados,
            quoting=csv.QUOTE_ALL
        )

        writer.writeheader()
        writer.writerows(registros.values())

    return jsonify({"status": "ok"})

# --------------------------------------------------
# ENVÍO FINAL + PDF
# --------------------------------------------------

@app.route("/enviar-validacion", methods=["POST"])
@login_required
def enviar_validacion():

    estado = session["estado"]

    ruta_entes = archivo_entes_estado(estado)
    ruta_codigos = archivo_codigos_estado(estado)
    ruta_cierre = archivo_cierre_estado(estado)

    if not os.path.exists(ruta_entes):
        return jsonify({"error": "No hay entes validados"}), 400

    # --------------------------------------------------
    # CONTEO INSTITUCIONES
    # --------------------------------------------------
    with open(ruta_entes, newline="", encoding="utf-8") as f:
        total_instituciones = sum(1 for _ in f) - 1

    instituciones_validadas = []

    if os.path.exists(ruta_codigos):
        with open(ruta_codigos, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                nombre = limpiar(r.get("nombre"))
                if nombre:
                    instituciones_validadas.append(nombre)

    total_codigos = len(instituciones_validadas)

    # --------------------------------------------------
    # CREAR PDF CON PLATYPUS + FONDO
    # --------------------------------------------------
    nombre_pdf = f"acuse_codigos_etica_{normalizar_texto(estado)}.pdf"
    ruta_pdf = os.path.join(carpeta_estado(estado), nombre_pdf)

    doc = SimpleDocTemplate(
        ruta_pdf,
        pagesize=LETTER,
        rightMargin=72,
        leftMargin=72,
        topMargin=120,   # Ajustado para que no choque con el encabezado del fondo
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
        fondo = ImageReader(RUTA_FONDO)
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

    # --------------------------------------------------
    # MARCAR COMO CERRADO
    # --------------------------------------------------
    with open(ruta_cierre, "w") as f:
        f.write("CERRADO")

    return jsonify({
        "status": "ok",
        "pdf": url_for(
            "static",
            filename=f"estados/{normalizar_texto(estado)}/{nombre_pdf}"
        )
    })

# --------------------------------------------------
# ARRANQUE
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
