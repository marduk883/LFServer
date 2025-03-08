import logging
from logging.handlers import RotatingFileHandler 
# Configure logging to write to a file with a specific format

def setup_logging():
    """Configure logging to write to files and console with specific formats and levels."""
    # Create a custom logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    file_handler_info = RotatingFileHandler('user_login_info.log', maxBytes=2000, backupCount=5)
    file_handler_info.setLevel(logging.INFO)

    file_handler_error = RotatingFileHandler('user_login_error.log', maxBytes=2000, backupCount=5)
    file_handler_error.setLevel(logging.ERROR)

    file_handler_critical = RotatingFileHandler('user_login_critical.log', maxBytes=2000, backupCount=5)
    file_handler_critical.setLevel(logging.CRITICAL)

    # Create formatters and add them to handlers
    formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(formatter)
    file_handler_info.setFormatter(formatter)
    file_handler_error.setFormatter(formatter)
    file_handler_critical.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler_info)
    logger.addHandler(file_handler_error)
    logger.addHandler(file_handler_critical)

    return logger

