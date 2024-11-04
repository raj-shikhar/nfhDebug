import json
import re
import subprocess
from docx import Document
import magic
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException
from lxml import etree
from PIL import Image
from moviepy.editor import VideoFileClip
from pydub import AudioSegment
import zipfile
import os
import sys
import requests
import io

####



class U:
    @staticmethod
    def process_html(html_content):
        """Process HTML content for errors or issues."""
        errors = []

        # Check for potential XSS vulnerabilities
        if "<script>" in html_content:
            errors.append("Potential XSS detected in HTML content.")

        # Use a regex to find any inline event handlers (e.g., onclick, onload)
        event_handlers = re.findall(r'\s*on[a-zA-Z]+\s*=', html_content)
        if event_handlers:
            errors.append(f"Inline event handlers detected: {event_handlers}")

        # Try to parse the HTML to check for well-formedness
        try:
            # Parse the HTML content
            parser = etree.HTMLParser()
            tree = etree.fromstring(html_content, parser)

            # Check for any <script> tags outside <head>
            scripts = tree.xpath("//script")
            for script in scripts:
                if script.getparent().tag != "head":
                    errors.append("Found <script> tag outside <head>.")

            # Additional checks for common vulnerabilities could go here...

        except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
            errors.append(f"HTML parsing error: {str(e)}")

        # Check for common security issues
        if '<iframe' in html_content:
            errors.append("Potential clickjacking risk with <iframe> tag detected.")

        # Optionally, you can check for specific tags or attributes that should not be present
        forbidden_tags = ['script', 'iframe', 'object', 'embed']
        for tag in forbidden_tags:
            if f'<{tag}' in html_content:
                errors.append(f"Forbidden tag <{tag}> detected.")

        return errors

    @staticmethod
    def process_json(json_string):
        """Process JSON content for malicious intent."""
        errors = []
        
        def detect_malicious_intent(json_obj):
            detected_errors = []
            for key, value in json_obj.items():
                if "<script>" in value:
                    detected_errors.append(f"Potential XSS detected in key '{key}': {value}")

                # Check for potential SQL injection attacks
                sql_pattern = re.compile(r"\b(?:select|insert|update|delete|drop|alter)\b", re.IGNORECASE)
                if re.search(sql_pattern, value):
                    detected_errors.append(f"Potential SQL injection detected in key '{key}': {value}")

            return detected_errors

        try:
            # Load JSON string into Python object
            json_obj = json.loads(json_string)

            # Validate the JSON object against an allowlist
            if isinstance(json_obj, dict):
                # Detect malicious intent
                errors = detect_malicious_intent(json_obj)
                return errors

            else:
                raise ValueError("Invalid JSON format: Only dictionary objects are allowed.")

        except json.JSONDecodeError as e:
            errors.append(f"Error decoding JSON: {e}")
            return errors

        except ValueError as e:
            errors.append(f"ValueError JSON: {e}")
            return errors
        
    @staticmethod
    def process_image(payload):
        """Process image content and return any errors."""
        try:
            from PIL import Image
            from io import BytesIO

            image = Image.open(BytesIO(payload))
            errors = []

            # Example check: check for image size
            if image.size[0] > 2000 or image.size[1] > 2000:
                errors.append("Warning: Image size exceeds 2000x2000.")

            return errors
        except Exception as e:
            return [f"Error processing image: {str(e)}"]

    @staticmethod
    def process_audio(payload):
        """Process audio content and return any errors."""
        try:
            from pydub import AudioSegment
            from io import BytesIO

            audio = AudioSegment.from_file(BytesIO(payload))
            errors = []

            # Example check: check for duration
            if len(audio) > 300000:  # 5 minutes in milliseconds
                errors.append("Warning: Audio duration exceeds 5 minutes.")

            return errors
        except Exception as e:
            return [f"Error processing audio: {str(e)}"]

    @staticmethod
    def process_video(payload):
        """Process video content and return any errors."""
        try:
            import cv2
            import numpy as np
            from io import BytesIO

            video = cv2.VideoCapture(BytesIO(payload))
            errors = []

            if not video.isOpened():
                errors.append("Error: Unable to open video file.")

            # Additional checks could be added here

            return errors
        except Exception as e:
            return [f"Error processing video: {str(e)}"]

    @staticmethod
    def process_text(payload):
        """Process plain text content and return any errors."""
        try:
            errors = []
            text = payload.decode('utf-8', errors='ignore')

            # Example check: check for length
            if len(text) > 1000:
                errors.append("Warning: Text content exceeds 1000 characters.")

            return errors
        except Exception as e:
            return [f"Error processing text: {str(e)}"]

    @staticmethod
    def process_binary(payload):
        """Process binary content and return any errors."""
        try:
            errors = []
            # Example check: file size
            if len(payload) > 1048576:  # 1 MB
                errors.append("Warning: Binary content exceeds 1 MB.")

            return errors
        except Exception as e:
            return [f"Error processing binary data: {str(e)}"]


####

def download_file(url):
    response = requests.get(url)
    if response.status_code == 200:
        return io.BytesIO(response.content)
    else:
        raise Exception(f"Failed to download file from {url}. Status code: {response.status_code}")
    


def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"File deleted: {file_path}")
    except Exception as e:
        print(f"Error deleting file: {str(e)}")

def process_html(html_content):
    errors = []
    options = Options()
    options.headless = True  # Run browser in headless mode
    driver = webdriver.Firefox(options=options)

    try:
        # Load HTML content
        driver.get("data:text/html;charset=utf-8," + str(html_content))
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

    except Exception as e:
        # Handle unexpected alert
        errors.append("Unexpected alert encountered: " + str(e))

    finally:
        # Close the browser
        driver.quit()

    # Return only the errors list
    return errors

def process_json(json_string):
    errors = []
    
    def detect_malicious_intent(json_obj):
        detected_errors = []
        for key, value in json_obj.items():
            if "<script>" in value:
                detected_errors.append(f"Potential XSS detected in key '{key}': {value}")

            # Check for potential SQL injection attacks
            sql_pattern = re.compile(r"\b(?:select|insert|update|delete|drop|alter)\b", re.IGNORECASE)
            if re.search(sql_pattern, value):
                detected_errors.append(f"Potential SQL injection detected in key '{key}': {value}")

            # Check for other security vulnerabilities...

        return detected_errors

    try:
        # Load JSON string into Python object
        json_obj = json.loads(json_string)

        # Validate the JSON object against an allowlist
        if isinstance(json_obj, dict):
            # Detect malicious intent
            errors = detect_malicious_intent(json_obj)
            if errors:
                return errors
            else:
                return []

        else:
            raise ValueError("Invalid JSON format: Only dictionary objects are allowed.")

    except json.JSONDecodeError as e:
        errors.append(f"Error decoding JSON: {e}")
        return errors

    except ValueError as e:
        errors.append(f"ValueError JSON: {e}")
        return errors

def process_binary(binary_data):
    errors = []
    # Execute the binary data in a controlled environment
    try:
        # Use subprocess.Popen for more flexibility
        process = subprocess.Popen(binary_data,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=True)

        # Capture output and errors
        stdout, stderr = process.communicate(timeout=30)  # Adjust timeout as needed
        # Return the output and errors
        errors.append(f"Output: {stdout.decode()}")
        errors.append(f"Error: {stderr.decode()}")

    except subprocess.CalledProcessError as e:
        errors.append(f"Called Process Error: {str(e)}")  # Store subprocess error

    except Exception as e:
        errors.append(f"Unexpected Error: {str(e)}")  # Store other unexpected errors

    # Return only the errors list
    return errors

def process_pdf(pdf):
    error=[]
    try:
        # Run Firefox with the PDF file as an argument
        subprocess.run(["firefox", pdf])
    except Exception as e:
        error.append["pdf file error:"+str(e)]
        # Handle any errors that occur

def process_xml(xml_data):
    xml_tree = etree.fromstring(xml_data)
    
    # Parse the XSLT file
    xslt_file="transform.xsl"
    xslt_tree = etree.parse(xslt_file)
    
    # Create an XSLT transformer
    transformer = etree.XSLT(xslt_tree)
    
    # Apply the transformation
    transformed_html = transformer(xml_tree)

    return process_html(transformed_html)

def process_doc(doc_data):
    errors = []
    try:
        # If doc_data is a URL, download the file
        if doc_data.startswith('http://') or doc_data.startswith('https://'):
            doc_data = download_file(doc_data)

        # Assuming the input is a DOCX file
        doc = Document(doc_data)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        # Process text as needed
        print(text)
    except Exception as e:
        errors.append(f"Document processing error: {str(e)}")
    
    delete_file(doc_data)
    return errors

def process_img(img_data):
    errors = []
    try:
        # If img_data is a URL, download the file
        if img_data.startswith('http://') or img_data.startswith('https://'):
            img_data = download_file(img_data)

        # Open image file
        img = Image.open(img_data)
        # Process image as needed
        img.show()  # Example: Display image
    except Exception as e:
        errors.append(f"Image processing error: {str(e)}")
    
    delete_file(img_data)
    return errors

def process_video(video_data):
    errors = []
    try:
        # If video_data is a URL, download the file
        if video_data.startswith('http://') or video_data.startswith('https://'):
            video_data = download_file(video_data)

        # Open video file
        video = VideoFileClip(video_data)
        # Process video as needed
        print(f"Video duration: {video.duration} seconds")
    except Exception as e:
        errors.append(f"Video processing error: {str(e)}")
    
    delete_file(video_data)
    return errors

def process_audio(audio_data):
    errors = []
    try:
        # If audio_data is a URL, download the file
        if audio_data.startswith('http://') or audio_data.startswith('https://'):
            audio_data = download_file(audio_data)

        # Open audio file
        audio = AudioSegment.from_file(audio_data)
        # Process audio as needed
        print(f"Audio duration: {len(audio)} milliseconds")
    except Exception as e:
        errors.append(f"Audio processing error: {str(e)}")

    delete_file(audio_data)
    return errors

def process_zip(zip_data):
    errors = []
    try:
        # If zip_data is a URL, download the file
        if zip_data.startswith('http://') or zip_data.startswith('https://'):
            zip_data = download_file(zip_data)

        # Extract contents of the ZIP file
        with zipfile.ZipFile(zip_data, 'r') as zip_ref:
            zip_ref.extractall('extracted_contents')
        # Process extracted contents as needed
        print("ZIP file extracted successfully.")
    except Exception as e:
        errors.append(f"ZIP file processing error: {str(e)}")
    return errors


