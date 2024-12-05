from sqlalchemy import Column, Integer, ForeignKey
from .db_manager import Base
from sqlalchemy.orm import relationship


class Ownership(Base):
    __tablename__ = "ownerships"

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    access_level_id = Column(Integer, ForeignKey("access_levels.id"))

    file = relationship("File", back_populates="ownerships")
    owner = relationship("User", back_populates="ownerships")
    access_level = relationship("AccessLevel", back_populates="ownership")
