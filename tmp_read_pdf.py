import sys
from pypdf import PdfReader

reader = PdfReader("c:\\Analizador de paquetes de redes\\Documento de Planificación y Diseño.pdf")
with open("c:\\Analizador de paquetes de redes\\tmp_pdf_text.txt", "w", encoding="utf-8") as f:
    for i, page in enumerate(reader.pages):
        f.write(f"--- Page {i+1} ---\n")
        f.write(page.extract_text() + "\n")
