from typing import Optional 
import streamlit as st
import cv2
import numpy as np
import requests
import time
from urllib.parse import urlparse
import html

# Detect and decode a QR code using opencv-python
def decode_qr_code(image):
    """
    Decodes a QR code from an image using OpenCV.
    Returns the decoded data and the bounding box points if found.
    """
    # Initialize the QRCode detector
    detector = cv2.QRCodeDetector()
    # Detect and decode
    data, bbox, _ = detector.detectAndDecode(image)
    return data, bbox

# Function to decode a shortened URL
def get_full_url(short_url: str) -> Optional[str]:
    """
    Function to expand the original URL
    """
    try:
        response = requests.head(
            short_url,
            allow_redirects=True,
            timeout=3,
            headers={"User-Agent": "SafeQRScanner/1.0"}
        )
        return response.url
    except requests.RequestException:
        return None

# Validate URL
def is_valid_url(url: str) -> bool:
    """
    Validate the URL first before sending network request. 
    Users may scan QR codes that contain: javascript payloads, embedded malware links
    malformed URLs, huge strings meant to crash applications, so we cha
    """
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)

# Basic and simple check
def detect_suspicious_url(url: str) -> list[str]:
    """
    Add basic potential fishing and dangerous domain checks: 
    Warn user if there is punycode, IP address links, suspicious TLDs, 
    emoji domains, or very long domains (phishing obfuscation)
    """
    warnings = []
    parsed = urlparse(url)

    # IP-address check
    if parsed.hostname and parsed.hostname.replace(".", "").isdigit():
        warnings.append("URL uses an IP address instead of a domain — often used in phishing.")

    # Long path or query
    if len(url) > 200:
        warnings.append("URL is unusually long — could be obfuscating malicious parameters.")

    # Punycode (IDN)
    if parsed.hostname and "xn--" in parsed.hostname:
        warnings.append("URL contains encoded characters (punycode) — verify the domain carefully.")

    # Suspicious TLDs
    bad_tlds = {"zip", "xyz", "click", "top", "quest"}
    if parsed.hostname and parsed.hostname.split(".")[-1] in bad_tlds:
        warnings.append("Domain uses a high-risk TLD commonly abused for phishing.")
    
    return warnings

# Main app
def main():
    # Page configuration
    st.set_page_config(
        page_title="Safe QR Scanner", 
        page_icon="🛡️"
    )

    # Title and introduction
    st.title("🛡️ Safe QR Code Scanner")
    st.markdown(
        """
            **Inspect before you click.** Scan a QR code using your camera. The app will extract the encoded text 
            so you can verify the URL or data *before* visiting the destination.
        """
    )
    st.divider()

    # Activate camera and ask to take a picture of the QR code
    img_file_buffer = st.camera_input("Take a picture of a QR Code")

    # If an image/buffer is taken
    if img_file_buffer is not None:

        # Convert the buffer to an image OpenCV can read
        bytes_data = img_file_buffer.getvalue()
        cv2_img = cv2.imdecode(np.frombuffer(bytes_data, np.uint8), cv2.IMREAD_COLOR)

        # Process the image and decode the QR code
        try:
            data, bbox = decode_qr_code(cv2_img)
        except Exception as e:
            st.error("Decoding failed due to an unexpected error.")
            return

        # Display Results if available
        if data:

            # Message to user that we found a QR code
            st.success("✅ QR Code Detected!")

            # Do basic checks
            with st.status("Checking URL...", expanded=True) as status:
                
                # Expand URL
                st.write("Expanding URL...")
                time.sleep(0.5)
                try:
                    expanded_url = get_full_url(data)        
                except:
                    expanded_url = data
                
                # Validate URL
                st.write("Validating URL...")
                time.sleep(0.5)
                is_valid = is_valid_url(expanded_url)        

                # Validate URL
                st.write("Checking for long or suspicious URL...")
                time.sleep(0.5)
                suspicious_warnings = detect_suspicious_url(expanded_url)  

                # Done
                time.sleep(0.5)
                status.update(
                    label="✅ Checks done", state="complete", expanded=False
                )
            
            # Display the raw data in a code block for safety
            st.subheader("Results")

            # Is it valid?
            if is_valid:
                st.success("✅ This seems to be a valid URL.")
            else:
                st.error("❌ This seems to be an invalid URL! Might be suspicious")

            # Give warnings
            if suspicious_warnings != []:
                for warn_ in suspicious_warnings:
                    st.warning(f"⚠️ {warn_}")

            # Give raw URL hidden in QR
            st.caption('Identified encoded URL in QR Code:')
            st.code(html.escape(data), language="text")

            # Give shortened URL if detected
            if expanded_url is not None:
                st.caption('After URL expansion:')
                st.code(html.escape(expanded_url), language="text")
            
            # Visual safety check
            if "http" in data:
                st.warning("⚠️ **Safety Check:** This looks like a website link. Please verify the domain carefully before opening.")
            else:
                st.info("ℹ️ This appears to be plain text or raw data.")

        # If no data avaialble (i.e., decoding failed), show message    
        else:
            st.error("❌ No QR code detected. Please try moving closer, or adjust the focus and lighting.")

if __name__ == "__main__":
    main()