# db_manager.py

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

Base = declarative_base()


def init_engine(db_path: str):
    """
    Initializes and returns a SQLAlchemy engine.

    Args:
        db_path (str): Database connection string.

    Returns:
        Engine: SQLAlchemy Engine instance.
    """
    engine = create_engine(db_path, echo=False)
    return engine
