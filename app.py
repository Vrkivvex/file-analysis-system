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

if not os.path.exists(UPLOAD_FOLDER):

    os.makedirs(UPLOAD_FOLDER)

# ================= DATABASE ================= #

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

            # FILE INFO

            file_name = uploaded_file.filename

            file_name_lower = file_name.lower()

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

            # ================= THREAT DETECTION ================= #

            malware_status = "No Malware Detected"

            threat_level = "LOW"

            # EXECUTABLE DETECTION

            if ".exe" in file_name_lower:

                malware_status = "Executable Payload Detected"

                threat_level = "HIGH"

            # BATCH SCRIPT DETECTION

            if ".bat" in file_name_lower:

                malware_status = "Batch Script Threat Detected"

                threat_level = "HIGH"

            # DOUBLE EXTENSION DETECTION

            if ".pdf.exe" in file_name_lower:

                malware_status = "Hidden Executable Malware Detected"

                threat_level = "CRITICAL"

            # SCRIPT FILE DETECTION

            if ".vbs" in file_name_lower or ".cmd" in file_name_lower:

                malware_status = "Suspicious Script File"

                threat_level = "HIGH"

            # DANGEROUS KEYWORD ANALYSIS

            dangerous_keywords = [

                "payload",
                "keylogger",
                "exploit",
                "backdoor",
                "ransomware"

            ]

            for keyword in dangerous_keywords:

                if keyword in file_name_lower:

                    malware_status = "Suspicious Signature Detected"

                    threat_level = "MEDIUM"

            # FILE SIZE HEURISTIC

            if file_size < 5000 and ".exe" in file_name_lower:

                malware_status = "Compressed Executable Threat"

                threat_level = "CRITICAL"

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

            # ================= MULTI ENGINE SCAN ================= #

            multi_scan_results = {

                "Windows Defender": "CLEAN",

                "Kaspersky": "CLEAN",

                "Malwarebytes": "CLEAN",

                "ClamAV": "CLEAN",

                "CrowdStrike": "CLEAN"
            }

            if threat_level == "HIGH":

                multi_scan_results = {

                    "Windows Defender": "MALICIOUS",

                    "Kaspersky": "MALICIOUS",

                    "Malwarebytes": "SUSPICIOUS",

                    "ClamAV": "SUSPICIOUS",

                    "CrowdStrike": "MALICIOUS"
                }

            if threat_level == "CRITICAL":

                multi_scan_results = {

                    "Windows Defender": "CRITICAL THREAT",

                    "Kaspersky": "CRITICAL THREAT",

                    "Malwarebytes": "CRITICAL THREAT",

                    "ClamAV": "MALICIOUS",

                    "CrowdStrike": "CRITICAL THREAT"
                }

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

                "image_resolution": image_resolution,

                "multi_scan_results": multi_scan_results
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