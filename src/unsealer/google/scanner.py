# src/unsealer/google/scanner.py

import os
from pathlib import Path
from PIL import Image
from pyzbar.pyzbar import decode
from typing import Set

def extract_uris_from_path(path_str: str) -> Set[str]:
    """
    Scans a file or directory for QR codes and extracts Google migration URIs.
    
    :param path_str: Path to an image file or a directory of images.
    :return: A set of unique migration URIs found.
    """
    found_uris = set()
    path = Path(path_str)
    
    if not path.exists():
        return found_uris

    # Define supported image formats
    supported_extensions = {'.png', '.jpg', '.jpeg', '.bmp', '.webp'}
    files = [path] if path.is_file() else list(path.iterdir())
    
    for f in files:
        if f.suffix.lower() not in supported_extensions:
            continue
        try:
            with Image.open(f) as img:
                # Convert to grayscale ('L') to improve recognition contrast
                decoded_objects = decode(img.convert('L'))
                for obj in decoded_objects:
                    content = obj.data.decode('utf-8')
                    if content.startswith("otpauth-migration://"):
                        found_uris.add(content)
        except Exception:
            # Skip unreadable or corrupted images
            continue
            
    return found_uris