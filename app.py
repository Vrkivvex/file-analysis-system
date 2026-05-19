import os
import time
import hashlib
import sqlite3
from flask import Flask, render_template, request
from PyPDF2 import PdfReader
from PIL import Image

app = Flask(__name__)

# ================= UPLOAD FOLDER ================= #

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create uploads folder automatically
if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)

# ================= SQLITE DATABASE ================= #

db = sqlite3.connect("database.db", check_same_thread=False)

cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS reports (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    file_name TEXT,

    file_path TEXT,

    file_size INTEGER,

    hash_value TEXT,

    status TEXT
)
""")

db.commit()

# ================= HASH FUNCTION ================= #

def generate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while chunk := file.read(4096):

            sha256.update(chunk)

    return sha256.hexdigest()

# ================= PDF ANALYSIS ================= #

def extract_pdf_data(file_path):

    try:

        reader = PdfReader(file_path)

        total_pages = len(reader.pages)

        return total_pages

    except:

        return 0

# ================= IMAGE ANALYSIS ================= #

def extract_image_data(file_path):

    try:

        image = Image.open(file_path)

        width, height = image.size

        return width, height

    except:

        return 0, 0

# ================= HOME ROUTE ================= #

@app.route("/", methods=["GET", "POST"])

def index():

    report = None

    if request.method == "POST":

        uploaded_file = request.files["file"]

        if uploaded_file:

            # SAVE FILE
            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                uploaded_file.filename
            )

            uploaded_file.save(file_path)

            # FILE DETAILS
            file_name = uploaded_file.filename

            file_size = os.path.getsize(file_path)

            file_extension = os.path.splitext(file_path)[1]

            creation_time = time.ctime(
                os.path.getctime(file_path)
            )

            modified_time = time.ctime(
                os.path.getmtime(file_path)
            )

            # HASH
            hash_value = generate_hash(file_path)

            # ================= MALWARE DETECTION ================= #

            suspicious_extensions = [
                ".exe",
                ".bat",
                ".cmd",
                ".vbs"
            ]

            dangerous_keywords = [
                "virus",
                "trojan",
                "malware",
                "hack",
                "keylogger"
            ]

            malware_status = "No Malware Detected"

            threat_level = "LOW"

            # EXTENSION CHECK
            if file_extension.lower() in suspicious_extensions:

                malware_status = "Suspicious Executable File"

                threat_level = "HIGH"

            # KEYWORD CHECK
            for keyword in dangerous_keywords:

                if keyword in file_name.lower():

                    malware_status = "Malicious Keyword Detected"

                    threat_level = "MEDIUM"

            # ================= PDF ANALYSIS ================= #

            pdf_pages = None

            if file_extension.lower() == ".pdf":

                pdf_pages = extract_pdf_data(file_path)

            # ================= IMAGE ANALYSIS ================= #

            image_resolution = None

            if file_extension.lower() in [
                ".png",
                ".jpg",
                ".jpeg"
            ]:

                width, height = extract_image_data(file_path)

                image_resolution = f"{width} x {height}"

            # ================= DATABASE INSERT ================= #

            sql = """
            INSERT INTO reports
            (file_name, file_path, file_size, hash_value, status)
            VALUES (?, ?, ?, ?, ?)
            """

            values = (
                file_name,
                file_path,
                file_size,
                hash_value,
                malware_status
            )

            cursor.execute(sql, values)

            db.commit()

            # ================= REPORT ================= #

            report = {

                "file_name": file_name,

                "file_type": file_extension,

                "file_size": file_size,

                "created": creation_time,

                "modified": modified_time,

                "hash": hash_value,

                "status": malware_status,

                "threat": threat_level,

                "pdf_pages": pdf_pages,

                "image_resolution": image_resolution
            }

    return render_template(
        "index.html",
        report=report
    )

# ================= REPORTS PAGE ================= #

@app.route("/reports")

def reports():

    cursor.execute("SELECT * FROM reports")

    rows = cursor.fetchall()

    return render_template(
        "reports.html",
        rows=rows
    )

# ================= RUN APP ================= #

if __name__ == "__main__":

    app.run(debug=True)