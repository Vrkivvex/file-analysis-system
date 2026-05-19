import os
import time
import hashlib
import mysql.connector
from flask import Flask, render_template, request
from PyPDF2 import PdfReader
from PIL import Image

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# DATABASE CONNECTION
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root123",
    database="file_analysis"
)

cursor = db.cursor()

# HASH FUNCTION
def generate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while chunk := file.read(4096):

            sha256.update(chunk)

    return sha256.hexdigest()

# PDF ANALYSIS
def extract_pdf_data(file_path):

    try:

        reader = PdfReader(file_path)

        total_pages = len(reader.pages)

        return total_pages

    except:

        return 0

# IMAGE ANALYSIS
def extract_image_data(file_path):

    try:

        image = Image.open(file_path)

        width, height = image.size

        return width, height

    except:

        return 0, 0

@app.route("/", methods=["GET", "POST"])

def index():

    report = None

    if request.method == "POST":

        uploaded_file = request.files["file"]

        if uploaded_file:

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                uploaded_file.filename
            )

            uploaded_file.save(file_path)

            file_name = uploaded_file.filename

            file_size = os.path.getsize(file_path)

            file_extension = os.path.splitext(file_path)[1]

            creation_time = time.ctime(os.path.getctime(file_path))

            modified_time = time.ctime(os.path.getmtime(file_path))

            hash_value = generate_hash(file_path)

            # MALWARE DETECTION
            suspicious_extensions = [
                ".exe",
                ".bat",
                ".cmd",
                ".vbs"
            ]

            malware_status = "No Malware Detected"

            threat_level = "LOW"

            if file_extension.lower() in suspicious_extensions:

                malware_status = "Suspicious Executable File"

                threat_level = "HIGH"

            # PDF ANALYSIS
            pdf_pages = None

            if file_extension.lower() == ".pdf":

                pdf_pages = extract_pdf_data(file_path)

            # IMAGE ANALYSIS
            image_resolution = None

            if file_extension.lower() in [".png", ".jpg", ".jpeg"]:

                width, height = extract_image_data(file_path)

                image_resolution = f"{width} x {height}"

            # DATABASE INSERT
            sql = """
            INSERT INTO reports
            (file_name, file_path, file_size, hash_value, status)
            VALUES (%s, %s, %s, %s, %s)
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

            report = {
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_extension,
                "created": creation_time,
                "modified": modified_time,
                "hash": hash_value,
                "status": malware_status,
                "threat": threat_level,
                "pdf_pages": pdf_pages,
                "image_resolution": image_resolution
            }

    return render_template("index.html", report=report)

@app.route("/reports")

def reports():

    cursor.execute("SELECT * FROM reports")

    rows = cursor.fetchall()

    return render_template("reports.html", rows=rows)

if __name__ == "__main__":

    app.run(debug=True)