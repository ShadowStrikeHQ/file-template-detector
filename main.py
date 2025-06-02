import argparse
import logging
import pathlib
import re
import os
import stat
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Identifies if a file conforms to a known template format.")
    parser.add_argument("file_path", type=str, help="The path to the file to analyze.")
    parser.add_argument("template_path", type=str, help="The path to the template file.")
    parser.add_argument("--log_level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")
    parser.add_argument("--hash_check", action="store_true", help="Enable hash check after template comparison.") # New argument to enable hash check
    return parser.parse_args()

def compare_file_to_template(file_path, template_path, hash_check):
    """
    Compares a file to a template definition.

    Args:
        file_path (str): The path to the file to analyze.
        template_path (str): The path to the template file.
        hash_check (bool): Flag to enable hash check after template comparison.

    Returns:
        bool: True if the file conforms to the template, False otherwise.
    """
    try:
        # Check if files exist and are readable
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False
        if not os.path.exists(template_path):
            logging.error(f"Template file not found: {template_path}")
            return False

        if not os.access(file_path, os.R_OK):
            logging.error(f"Cannot read file: {file_path} - insufficient permissions.")
            return False

        if not os.access(template_path, os.R_OK):
            logging.error(f"Cannot read template file: {template_path} - insufficient permissions.")
            return False
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            file_content = f.readlines()

        with open(template_path, 'r', encoding='utf-8', errors='ignore') as t:
            template_content = t.readlines()

        # Basic line-by-line comparison (can be extended with regex or more complex logic)
        if len(file_content) != len(template_content):
            logging.warning("File and template have different number of lines.")
            #continue checking anyway, in case this difference is expected
            #return False

        match = True
        for i in range(min(len(file_content), len(template_content))):
            template_line = template_content[i].strip()
            file_line = file_content[i].strip()

            # If template line is a regex, check file line against it.  Otherwise, do exact match.
            if template_line.startswith("REGEX:"):
                regex = template_line[6:].strip() #Extract the regex
                if not re.match(regex, file_line):
                    logging.warning(f"Line {i+1} does not match the regex: {regex}")
                    match = False
                    break
            elif template_line != file_line:
                logging.warning(f"Line {i+1} does not match. Template: {template_line}, File: {file_line}")
                match = False
                break

        if hash_check and match:  #Perform hash check only if the basic structure matches
             #Calculate hashes
            file_hash = calculate_file_hash(file_path)
            template_hash = calculate_file_hash(template_path)

            if file_hash == template_hash:
                logging.info(f"File hash {file_hash} matches template hash {template_hash}.")
            else:
                logging.warning(f"File hash {file_hash} DOES NOT match template hash {template_hash}.")
                match = False #consider a failed hash check a non-match.

        return match


    except FileNotFoundError:
        logging.error("File not found during comparison.")
        return False
    except Exception as e:
        logging.exception(f"An error occurred during comparison: {e}")
        return False

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculates the hash of a file."""
    hasher = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as afile: #Open in binary mode.  Crucial for hash stability
            buf = afile.read()
            hasher.update(buf)
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

    return hasher.hexdigest()

def is_file_secure(filepath):
    """
    Performs security checks on the file.
    Args:
        filepath (str): The path to the file.
    Returns:
        bool: True if the file passes security checks, False otherwise.
    """

    try:
        file_path = pathlib.Path(filepath)

        # Check for symlinks (avoid following them)
        if file_path.is_symlink():
            logging.warning(f"File is a symbolic link: {filepath}.  Skipping security checks.")
            return False # Or raise an exception if symlinks should be treated as critical errors

        # Check file permissions (restrictive permissions are preferred)
        st = file_path.stat()
        permissions = stat.filemode(st.st_mode)
        # Example: Check if world-writable bit is set (highly insecure)
        if st.st_mode & stat.S_IWOTH:
            logging.warning(f"File has world-writable permissions: {filepath} ({permissions})")
            return False  # Insecure

         # Check file ownership (owned by root or a system account is preferred)
        if st.st_uid == 0:  # Root user
            logging.debug(f"File owned by root: {filepath}")
        elif st.st_uid < 1000:  # System account (UIDs below 1000 are usually reserved)
            logging.debug(f"File owned by system account (UID {st.st_uid}): {filepath}")
        else:
            logging.warning(f"File not owned by root or a system account (UID {st.st_uid}): {filepath}")
            #Consider failing the check if a non-system account owns it.
            return False


        # Check file size (prevent excessively large files)
        file_size = file_path.stat().st_size
        max_size = 10 * 1024 * 1024  # 10 MB limit
        if file_size > max_size:
            logging.warning(f"File exceeds maximum allowed size ({file_size} bytes > {max_size} bytes): {filepath}")
            return False

        return True # All checks passed

    except Exception as e:
        logging.error(f"Error during security checks for {filepath}: {e}")
        return False


def main():
    """
    Main function to execute the file template detector.
    """
    args = setup_argparse()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    # Input validation
    file_path = args.file_path
    template_path = args.template_path

    if not isinstance(file_path, str):
        logging.error("File path must be a string.")
        return

    if not isinstance(template_path, str):
        logging.error("Template path must be a string.")
        return


    if not is_file_secure(file_path):
        logging.error("File failed security checks. Aborting template comparison.")
        return
    

    # Call the comparison function
    if compare_file_to_template(file_path, template_path, args.hash_check):
        logging.info("File conforms to the template.")
    else:
        logging.warning("File does NOT conform to the template.")

if __name__ == "__main__":
    # Usage Examples:
    # 1. Basic Usage:
    # python main.py config.txt template.txt
    #
    # 2. With Debug Logging:
    # python main.py config.txt template.txt --log_level DEBUG
    #
    # 3. With Hash Check:
    # python main.py config.txt template.txt --hash_check
    #
    # Template examples:
    # Add "REGEX:^Version: \d+\.\d+$"  to template.txt to check the corresponding line in config.txt is a version number
    main()