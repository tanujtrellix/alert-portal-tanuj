# Postgress db related operations like connect,close, execute_statement
import psycopg2
import json
from utils.logger_util import setup_logger

logger = setup_logger(__name__)

class Db_connection:
    def __init__(self):
        """Initialize the database connection."""
        self.config = self.load_config('db/config.json')
        # Access dictionary values
        self.db_config = self.config.get('database', { })
        self.connection = None
        self.cursor = None

    def load_config(self, file_path):
        """Load the configuration from a JSON file."""
        with open(file_path, 'r') as file:
            config = json.load(file)
        return config

    def connect(self):
        """Connect to the SQLite database."""

        db_params = {
            'host': self.db_config.get('HOST'),
            'database': self.db_config.get('DATABASE'),
            'user':self.db_config.get('USER'),
            'password': self.db_config.get('PASSWORD')
            }
        logger.info(f"Connecting to host :{db_params['host']} and database :{db_params['database']}")
        if self.connection is None:
            self.connection = psycopg2.connect(**db_params)
            self.cursor = self.connection.cursor()
            logger.info('Successfully connected to database')

    def close(self):
        """Close the SQLite database connection."""
        if self.cursor is not None:
            self.cursor.close()
        if self.connection is not None:
            self.connection.close()
        logger.info('Database connection closed')

    def execute_statement(self, sql_query, data=(), fetch=False):
        """Executes sql statement"""
        try:
            logger.info(f"Executing sql query :{sql_query}")
            self.cursor.execute(sql_query, data)
            self.connection.commit()
            if fetch:
                result = self.cursor.fetchall()
                return result
        except Exception as error:
            logger.error(f"Error: {error}")
