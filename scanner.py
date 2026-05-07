MAGIC_HEADERS = {
    b"\x25\x50\x44\x46": "PDF",
    b"\xFF\xD8\xFF": "JPEG",
    b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": "PNG",
    b"\x4D\x5A": "EXE",
    b"\x50\x4B\x03\x04": "ZIP/Office"
}

def identify_file(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(10)
            for signature, file_type in MAGIC_HEADERS.items():
                if header.startswith(signature):
                    return file_type
        return "UNKNOWN"
    except Exception as e:
        return f"Error: {e}"
