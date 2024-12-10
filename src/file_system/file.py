from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship, Session
from typing import Optional
from .db_manager import Base
from .access_level import AccessLevel
from pathlib import Path
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import exists, and_
from .ownership import Ownership


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    ftp_path = Column(String, nullable=False)
    creator_username = Column(String, nullable=False)
    is_dir = Column(Boolean, nullable=False, default=False)
    anonymous_access_level_id = Column(Integer, ForeignKey("access_levels.id"))

    ownerships = relationship("Ownership", back_populates="file")
    anonymous_access = relationship("AccessLevel",
                                    foreign_keys=[anonymous_access_level_id])

    def __init__(self,
                 ftp_path: str,
                 is_dir: bool = False,
                 creator_username: str = None,
                 anonymous_access_level: Optional['AccessLevel'] = None):
        self.ftp_path = ftp_path
        self.is_dir = is_dir
        self.creator_username = creator_username

        if anonymous_access_level:
            self.anonymous_access = anonymous_access_level

    def set_anonymous_access(self,
                             session: Session,
                             can_read: bool = True,
                             can_write: bool = False,
                             can_execute: bool = False) -> None:
        access_level = AccessLevel(
            can_read=can_read,
            can_write=can_write,
            can_execute=can_execute
        )
        session.add(access_level)
        self.anonymous_access = access_level

    def update_anonymous_access(self,
                                session: Session,
                                can_read: bool = True,
                                can_write: bool = False,
                                can_execute: bool = False) -> None:
        if self.anonymous_access:
            self.anonymous_access.can_read = can_read
            self.anonymous_access.can_write = can_write
            self.anonymous_access.can_execute = can_execute

        else:
            self.set_anonymous_access(
                session,
                can_read=can_read,
                can_write=can_write,
                can_execute=can_execute
            )

