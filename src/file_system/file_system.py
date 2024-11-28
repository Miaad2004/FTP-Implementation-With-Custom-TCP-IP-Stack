from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession
from sqlalchemy.engine import Engine
import os
from functools import wraps
from typing import Callable, Optional, List
from .file import File
from .user import User, UserExistsError
from .ownership import Ownership
from .access_level import AccessLevel
from .db_manager import Base, create_engine
from src.common.config import config_handler
import time


class AuthenticationError(Exception):
    """Exception raised when a user is not authenticated."""

    pass


class FileSystem:
    def __init__(self,
                 root_dir: str = None,
                 db_path: str = None) -> None:
        """
        Initialize the FileSystem with a root directory and database path.

        :param root_dir: The root directory for the file system.
        :param db_path: The path to the database.
        """
        if not root_dir:
            root_dir = config_handler.get("file_system_root_dir")
    
        if not db_path:
            db_path = config_handler.get("file_system_db_path")        
        
        self.root: str = root_dir
        self.engine: Engine = create_engine(db_path)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session: SQLAlchemySession = Session()
        self.current_user: Optional[User] = None
        self.current_ftp_dir = "/"

    def login_required(f: Callable) -> Callable:
        """
        Decorator to ensure the user is logged in before accessing the method.

        :param f: The function to wrap.
        :return: The wrapped function.
        """

        @wraps(f)
        def wrapper(self, *args, **kwargs):
            if not hasattr(self, "current_user") or not self.current_user:
                raise AuthenticationError("User not logged in")
            return f(self, *args, **kwargs)

        return wrapper

    def require_create_permission(f: Callable) -> Callable:
        """
        Decorator to ensure the user has create permissions before
        accessing the method.

        :param f: The function to wrap.
        :return: The wrapped function.
        """

        @wraps(f)
        def wrapper(self, *args, **kwargs):
            if not self.current_user.can_create:
                raise PermissionError("User doesn't have creation privileges")
            return f(self, *args, **kwargs)

        return wrapper

    def create_user(self,
                    username: str,
                    password: str,
                    can_create: bool) -> User:
        """
        Create a new user.

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param can_create: Whether the user has create permissions.
        :return: The created user.
        :raises UserExistsError: If the user already exists.
        """
        if self.get_user(username):
            raise UserExistsError(f"User {username} already exists")

        user = User(username=username,
                    password=User._hash_password(password),
                    can_create=can_create)

        try:
            os.makedirs(os.path.join(self.root, username))
            self.session.add(user)
            self.session.commit()
            return user

        except Exception:
            self.session.rollback()
            raise

    @login_required
    def delete_user(self) -> None:
        """
        Delete the current user and all their files where they are the owner.

        :raises AuthenticationError: If user not logged in
        """
        if not self.current_user:
            raise AuthenticationError("User not logged in")

        try:
            # Delete owned files
            owned_files = self.session.query(File)\
                         .join(Ownership)\
                         .join(AccessLevel)\
                         .filter(Ownership.user_id == self.current_user.id)\
                         .filter(AccessLevel.is_owner)\
                         .all()

            for file in owned_files:
                file_path = self.fs_path_to_full_path(file.fs_path, file.name)
                if os.path.exists(file_path):
                    os.remove(file_path)

                file_ownerships = self.session.query(Ownership)\
                                              .filter_by(file_id=file.id)\
                                              .all()

                for ownership in file_ownerships:
                    self.session.delete(ownership.access_level)
                    self.session.delete(ownership)

                self.session.delete(file)

            # Delete all ownerships (for shared files)
            user_ownerships = self.session.query(Ownership)\
                                  .filter_by(user_id=self.current_user.id)\
                                  .all()

            for ownership in user_ownerships:
                self.session.delete(ownership.access_level)
                self.session.delete(ownership)

            # Delete files on the actual FS
            user_dir = os.path.join(self.root, self.current_user.username)
            if os.path.exists(user_dir):
                for root, dirs, files in os.walk(user_dir, topdown=False):
                    try:
                        os.rmdir(root)
                    except OSError:
                        pass

            # Delete the user
            self.session.delete(self.current_user)
            self.session.commit()
            self.current_user = None

        except Exception:
            self.session.rollback()
            raise

    def get_user(self, username: str) -> Optional[User]:
        """
        Get a user by username.

        :param username: The username of the user.
        :return: The user if found, otherwise None.
        """
        return self.session.query(User).filter_by(username=username).first()

    def login(self, username: str, password: str) -> bool:
        """
        Log in a user.

        :param username: The username of the user.
        :param password: The password of the user.
        :return: True if login is successful, otherwise False.
        """
        user = self.get_user(username)
        if user and user.authenticate(password):
            self.current_user = user
            return True

        return False

    def logout(self) -> None:
        """Log out the current user."""
        self.current_user = None

    def ftp_path_to_fs(self, ftp_path: str) -> str:
        """
        """
        return os.path.normpath(
            os.path.join(self.current_user.username, ftp_path)
            )

    def fs_path_to_ftp(self, fs_path: str) -> str:
        """
        
        """
        path_parts = os.path.split(fs_path)
        path_parts = path_parts[path_parts.index(self.current_user.username):]
        return os.path.normpath(os.path.join(*path_parts))
    
    def fs_path_to_full_path(self, fs_path: str, file_name: str = None) -> str:
        """
        Convert a file system path to a real path.

        :param fs_path: The file system path.
        :param file_name: The name of the file.
        :return: The real path.
        """
        fs_path = fs_path.replace("\\", "/").strip("/")
        
        if file_name:
            return os.path.normpath(os.path.join(self.root, fs_path, file_name))
        
        else:
            return os.path.normpath(os.path.join(self.root, fs_path))

    @login_required
    @require_create_permission
    def create_file(self, ftp_path: str, file_name: str) -> str:
        """
        Create a new file.

        :param ftp_path: The FTP path where the file will be created.
        :param file_name: The name of the file.
        :return: The real path of the created file.
        :raises FileExistsError: If the file already exists.
        """

        ftp_path = ftp_path.replace("\\", "/").strip("/")

        fs_path = self.ftp_path_to_fs(ftp_path)
        file = File(fs_path=fs_path, ftp_path=ftp_path, name=file_name)

        try:
            full_path = self.fs_path_to_full_path(fs_path, file_name)

            if os.path.exists(full_path):
                raise FileExistsError("File already exists")

            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "w") as f:
                f.write("")

            access_level = AccessLevel(can_read=True, can_write=True,
                                       can_delete=True, is_owner=True)
            ownership = Ownership(file=file, owner=self.current_user,
                                  access_level=access_level)

            self.session.add(file)
            self.session.add(access_level)
            self.session.add(ownership)
            self.session.commit()

            return full_path

        except Exception:
            self.session.rollback()
            raise
    
    @login_required
    def has_access_to_dir(self, dir: str):
        if os.path.split(dir)[0] == self.current_user.username:
            return True
    
    @login_required
    def mkdir(self, ftp_path: str):
        fs_path = self.ftp_path_to_fs(ftp_path)
        if not self.has_access_to_dir(fs_path):
            raise PermissionError("No permission to create directory")
        
        try:
            full_path = self.fs_path_to_full_path(fs_path)
            os.mkdir(full_path)
        
        except Exception:
            raise

    @login_required
    def read_file(self, ftp_file_path: str, file_name: str) -> str:
        """
        Read a file.

        :param ftp_file_path: The FTP path of the file.
        :param file_name: The name of the file.
        :return: The real path of the file.
        :raises FileNotFoundError: If the file is not found.
        :raises PermissionError: If the user does not have read permission.
        """
        file = self.session.query(File)\
                   .filter_by(ftp_path=ftp_file_path, name=file_name)\
                   .first()
        
        if not file:
            raise FileNotFoundError("File not found")

        ownership = self.session.query(Ownership)\
                        .filter_by(file_id=file.id,
                                   user_id=self.current_user.id)\
                        .first()

        if not ownership or not ownership.access_level.can_read:
            raise PermissionError("No read permission")

        return self.fs_path_to_full_path(file.fs_path, file.name)

    @login_required
    def delete_file(self, ftp_file_path: str, file_name: str) -> None:
        """
        Delete a file.

        :param ftp_file_path: The FTP path of the file.
        :param file_name: The name of the file.
        :raises FileNotFoundError: If the file is not found.
        :raises PermissionError: If the user does not have delete permission.
        """
        ftp_file_path = ftp_file_path.replace("\\", "/").strip("/")

        file = (self.session.query(File)
                .filter_by(ftp_path=ftp_file_path, name=file_name)
                .first())

        if not file:
            raise FileNotFoundError("File not found")

        ownership = (self.session.query(Ownership)
                     .filter_by(file_id=file.id, user_id=self.current_user.id)
                     .first())

        if not ownership or not ownership.access_level.can_delete:
            raise PermissionError("No delete permission")

        try:
            os.remove(self.fs_path_to_full_path(file.fs_path, file.name))
            self.session.delete(file)
            self.session.commit()

        except Exception:
            self.session.rollback()
            raise

    @login_required
    def list_curr_user_files(self) -> List[File]:
        """
        List all files owned or accessible by the current user.

        :return: A list of files.
        """
        files = (self.session.query(File)
                 .join(Ownership)
                 .filter(Ownership.user_id == self.current_user.id)
                 .all())
        
        return files
    
    @login_required
    def list_dir(self, ftp_path: str) -> List[dict]:
        """
        List all files in a directory visible to current user.

        :param ftp_path: The FTP path of the directory.
        :return: List of file info dicts for FTP LIST format.
        """
        # Convert FTP path to filesystem path
        fs_path = self.ftp_path_to_fs(ftp_path)
        # print(f"current_user: {self.current_user}")
        # print(self.current_user.username)
        # print(fs_path)
        # Query files in this directory that user can access
        files = (self.session.query(File)
                 .join(Ownership)
                 .filter(Ownership.user_id == self.current_user.id)
                 .filter(File.fs_path == fs_path)
                 .all())
        
        file_list = []
        
        for file in files:
            # Get file stats
            full_path = self.fs_path_to_full_path(file.fs_path, file.name)
            stats = os.stat(full_path)
            
            # Get permissions
            ownership = (self.session.query(Ownership)
                        .filter_by(file_id=file.id, user_id=self.current_user.id)
                        .first())
            
            # Format permissions
            perms = "r" if ownership.access_level.can_read else "-"
            perms += "w" if ownership.access_level.can_write else "-" 
            perms += "x" if os.access(full_path, os.X_OK) else "-"
            
            # Format timestamp
            ts = stats.st_mtime
            date = time.strftime("%b %d %H:%M", time.localtime(ts))

            # Build file info dict
            file_info = {
                'type': '-',  # Regular file
                'permissions': perms * 3, # User/group/other all same
                'owner': self.current_user.username,
                'group': self.current_user.username,
                'size': stats.st_size,
                'date': date,
                'name': file.name
            }
            
            file_list.append(file_info)
            
        return file_list
    
    @login_required
    def chmod(
        self,
        target_username: str,
        ftp_file_path: str,
        file_name: str,
        can_read: bool,
        can_write: bool,
        can_delete: bool,
    ) -> None:
        """
        Change the permissions of a file for a target user.

        :param target_username: The username of the target user.
        :param ftp_file_path: The FTP path of the file.
        :param file_name: The name of the file.
        :param can_read: Whether the target user can read the file.
        :param can_write: Whether the target user can write to the file.
        :param can_delete: Whether the target user can delete the file.
        :raises FileNotFoundError: If the file is not found.
        :raises PermissionError: If the current user does not have permission.
        :raises ValueError: If the target user is not found.
        """
        ftp_file_path = ftp_file_path.replace("\\", "/").strip("/")
        fs_path = os.path.normpath(
            os.path.join(self.current_user.username, ftp_file_path)
        ).replace("\\", "/")

        file = (self.session.query(File)
                .filter_by(fs_path=fs_path, name=file_name)
                .first())

        if not file:
            raise FileNotFoundError("File not found")

        current_ownership = (self.session.query(Ownership)
                             .filter_by(file_id=file.id,
                                        user_id=self.current_user.id)
                             .first())

        if not current_ownership or\
           not current_ownership.access_level.is_owner:
            raise PermissionError("No permission to change permissions")

        target_user = self.get_user(target_username)
        if not target_user:
            raise ValueError("Target user not found")

        try:
            existing_ownership = (self.session.query(Ownership)
                                  .filter_by(file_id=file.id,
                                             user_id=target_user.id)
                                  .first())

            if existing_ownership:
                access_level = existing_ownership.access_level
                access_level.can_read = can_read
                access_level.can_write = can_write
                access_level.can_delete = can_delete
                self.session.add(access_level)
            
            else:
                access_level = AccessLevel(can_read=can_read,
                                           can_write=can_write,
                                           can_delete=can_delete,
                                           is_owner=False,)
                ownership = Ownership(file=file,
                                      owner=target_user,
                                      access_level=access_level)
        
                self.session.add(access_level)
                self.session.add(ownership)

            self.session.commit()

        except Exception:
            self.session.rollback()
            raise
