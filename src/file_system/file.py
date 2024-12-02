from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship
from .db_manager import Base


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    ftp_path = Column(String, nullable=False)
    name = Column(String, nullable=False)
    is_dir = Column(Boolean, nullable=False, default=False)

    ownerships = relationship("Ownership", back_populates="file")
