Tablero de Seguimiento a los Acuerdos del Sistema Nacional Anticorrupción

Descripción

Esta aplicación web permite a los Sistemas Estatales Anticorrupción
(SEA) reportar y dar seguimiento al avance en la emisión de Códigos de
Ética, conforme al Artículo 16 de la Ley General de Responsabilidades
Administrativas (LGRA).

El sistema cuenta con: Módulo de captura y verificación y un tablero
público con resultados en tiempo real

Stack tecnológico
Backend: Python 3.11 + Flask 
Base de datos: Supabase (PostgreSQL)
Autenticación: Supabase Auth (JWT) 
Almacenamiento: Supabase Storage
Frontend: HTML + CSS + JavaScript
Visualización: Chart.js / Plotly.js 
Generación PDF: ReportLab
Contenerización: Docker + Gunicorn

Instalación
git clone https://github.com/ArieBrito/reporte-codigos-etica cd
reporte-codigos-etica docker compose up -d
