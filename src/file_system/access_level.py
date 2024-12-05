from sqlalchemy import Column, Integer, Boolean
from sqlalchemy.orm import relationship
from .db_manager import Base


class AccessLevel(Base):
    __tablename__ = "access_levels"

    id = Column(Integer, primary_key=True)
    can_read = Column(Boolean, default=False)
    can_write = Column(Boolean, default=False)
    can_execute = Column(Boolean, default=False)
    is_original_creator = Column(Boolean, nullable=False, default=False)

    ownership = relationship("Ownership", back_populates="access_level")
