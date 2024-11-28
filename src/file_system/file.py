from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from .db_manager import Base


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    fs_path = Column(String, nullable=False)
    ftp_path = Column(String, nullable=False)
    name = Column(String, nullable=False)

    ownerships = relationship("Ownership", back_populates="file")
