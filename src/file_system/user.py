import hashlib
from sqlalchemy import Boolean, Column, Integer, String
from .db_manager import Base
from sqlalchemy.orm import relationship


class UserExistsError(Exception):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    can_create = Column(Boolean, default=False)

    ownerships = relationship("Ownership", back_populates="owner")

    @staticmethod
    def _hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, password):
        return self.password == self._hash_password(password)
