import shutil
from flask import Flask, request, jsonify
from sqlalchemy.exc import IntegrityError
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging
import logging.handlers
import uuid
import os
from datetime import datetime
from config import DevelopmentConfig

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
auth = HTTPBasicAuth()

# Configure logging
handler = logging.handlers.RotatingFileHandler(
    app.config['LOG_FILE'], maxBytes=10000000, backupCount=5
)
handler.setLevel(logging.getLevelName(app.config['LOG_LEVEL']))
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:/postgres')
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class Notification(Base):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True)
    content_type = Column(String(50))
    data = Column(Text)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Directory to save received data
SAVE_DIR = "received_data"
PROCESSED_DIR = "processed"
os.makedirs(SAVE_DIR, exist_ok=True)

# User authentication
@auth.verify_password
def verify_password(username, password):
    users = app.config['USERS']
    if username in users and check_password_hash(users.get(username), password):
        return username

@app.route('/notify', methods=['POST'])
@auth.login_required(optional=True)
def notify():
    try:
        content_type = request.content_type
        data = None
        file_extension = None

        if content_type in ['application/json', 'application/xml', 'text/plain']:
            data = request.get_data().decode('utf-8')
            if content_type == 'application/json':
                file_extension = '.json'
            elif content_type == 'application/xml':
                file_extension = '.xml'
            elif content_type == 'text/plain':
                file_extension = '.txt'
        else:
            app.logger.warning("Unsupported Media Type")
            return "Unsupported Media Type", 415

        if data:
            # Save data to file
            filename = str(uuid.uuid4()) + file_extension
            file_path = os.path.join(SAVE_DIR, filename)
            with open(file_path, 'w') as file:
                file.write(data)
            app.logger.info(f"Saved data to file {file_path}")

            # Save data to database
            notification = Notification(content_type=content_type, data=data)
            try:
                session.add(notification)
                session.commit()
                app.logger.info(f"Saved data to database with id {notification.id}")
                shutil.move(file_path, os.path.join(PROCESSED_DIR, filename))
            except IntegrityError as e:
                session.rollback()  # Roll back the session to a clean state
                if 'duplicate key value violates unique constraint' in str(e):
                    return jsonify({"error": "Duplicate entry detected."}), 409
                else:
                    return jsonify({"error": "An error occurred."}), 500


            return jsonify({"status": "success", "id": notification.id, "file": filename}), 200

    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))