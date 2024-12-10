import os
import time
import logging
import shutil
import threading
from functools import wraps
from pathlib import Path, PurePath
from typing import Callable, Optional, List, Union, Dict, Tuple
from threading import Lock
from contextlib import contextmanager

from pathvalidate import is_valid_filename
from sqlalchemy import or_, and_
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.engine import Engine

from .file import File
from .user import User, UserExistsError
from .ownership import Ownership
from .access_level import AccessLevel
from .db_manager import Base, create_engine
from src.common.config import config_handler


class AuthenticationError(Exception):
    """Exception raised when a user is not authenticated."""

    pass


class FileSystem:
    def __init__(self, root_dir: str = None, db_path: str = None) -> None:
        """
        Initialize the FileSystem object.

        :param root_dir: Root directory for the file system.
        :param db_path: Path to the database.
        """
        # Thread-local storage
        self.thread_local = threading.local()

        # Locks
        self._file_ops_lock = Lock()
        self._user_ops_lock = Lock()
        self._user_ops_lock2 = Lock()

        # Set root directory
        if not root_dir:
            root_dir = Path(config_handler.get("file_system_root_dir"))
            if not root_dir.exists():
                raise ValueError("Root directory does not exist")
        self.root: Path = root_dir

        # Set database path
        if not db_path:
            db_path = config_handler.get("file_system_db_path")
            # if not os.access(db_path, os.W_OK):
            #     raise PermissionError(f"No write permission for database at {db_path}")
            
        self.engine: Engine = create_engine(db_path)

        # Initialize database
        Base.metadata.create_all(self.engine)
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)

        # Logger
        self.logger = logging.getLogger(__name__)

    def get_current_user(self, db_session):
        """
        Get the current user from the database session.

        :param db_session: Database session.
        :return: Current user object or None.
        """
        if not self.current_user_id:
            return None

        return (db_session.query(User)
                .filter_by(id=self.current_user_id)
                .first())

    @property
    def current_ftp_dir(self) -> Optional[PurePath]:
        """
        Get the current FTP directory.

        :return: Current FTP directory.
        """
        with self._user_ops_lock:
            return getattr(self.thread_local, "current_ftp_dir", None)

    @current_ftp_dir.setter
    def current_ftp_dir(self, value: Optional[PurePath]):
        """
        Set the current FTP directory.

        :param value: New FTP directory.
        """
        with self._user_ops_lock:
            self.thread_local.current_ftp_dir = value

    @property
    def current_user_id(self) -> Optional[int]:
        """
        Get the current user ID.

        :return: Current user ID.
        """
        with self._user_ops_lock:
            return getattr(self.thread_local, "current_user_id", None)

    @current_user_id.setter
    def current_user_id(self, value: Optional[int]):
        """
        Set the current user ID.

        :param value: New user ID.
        """
        with self._user_ops_lock:
            self.thread_local.current_user_id = value

    @property
    def current_username(self) -> Optional[str]:
        """
        Get the current username.

        :return: Current username.
        """
        with self._user_ops_lock:
            return getattr(self.thread_local, "current_username", None)

    @current_username.setter
    def current_username(self, value: Optional[str]):
        """
        Set the current username.

        :param value: New username.
        """
        with self._user_ops_lock:
            self.thread_local.current_username = value

    @contextmanager
    def get_db_session(self):
        """
        Context manager for database session.

        :yield: Database session.
        """
        session = self.Session()

        try:
            yield session
            session.commit()

        except Exception:
            session.rollback()
            raise

        finally:
            session.close()
            self.Session.remove()

    @contextmanager
    def _atomic_file_operation(self):
        """
        Context manager for atomic file operations.

        :yield: None.
        """
        acquired = False

        try:
            self._file_ops_lock.acquire()
            acquired = True
            yield

        finally:
            if acquired:
                self._file_ops_lock.release()

    def login_required(f: Callable) -> Callable:
        """
        Decorator to ensure the user is logged in.

        :param f: Function to wrap.
        :return: Wrapped function.
        """

        @wraps(f)
        def wrapper(self, *args, **kwargs):
            if not hasattr(self, "current_username") or\
                        not self.current_username:
                raise AuthenticationError("User not logged in")
            return f(self, *args, **kwargs)

        return wrapper

    def resolve_path(path_param: str):
        """
        Decorator to resolve FTP paths to filesystem paths.

        :param path_param: Parameter name for the path.
        :return: Wrapped function.
        """

        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def wrapper(self, *args, **kwargs) -> Union[str, PurePath]:
                path = None

                if path_param in kwargs:
                    path = kwargs[path_param]

                elif args:
                    import inspect

                    params = inspect.signature(f).parameters

                    if path_param in params:
                        param_position = list(params.keys()).index(
                            path_param) - 1
                        path = args[param_position]

                if path is None:
                    path = self.current_ftp_dir

                if path:
                    path = PurePath(path)

                # Handle relative paths
                if not path.is_absolute():
                    if not self.current_ftp_dir:
                        raise ValueError(
                            "No current directory set for\
                            relative path"
                        )

                    path = PurePath(self.current_ftp_dir) / path

                # Update args
                if path_param in kwargs:
                    kwargs[path_param] = path

                elif args:
                    args = list(args)
                    args[param_position] = path

                return f(self, *args, **kwargs)

            return wrapper

        return decorator

    def auth_create_user(
        self, username: str, password: str, can_create: bool
    ) -> User:
        """
        Create a new user.

        :param username: Username.
        :param password: Password.
        :param can_create: Whether the user can create files.
        :return: Created user object.
        """
        with self._user_ops_lock:
            with self.get_db_session() as session:
                if self.auth_get_username(username):
                    raise UserExistsError(f"User {username} already exists")

                user = User(
                    username=username,
                    password=User._hash_password(password),
                    can_create=can_create,
                )

                try:
                    with self._atomic_file_operation():
                        os.makedirs(os.path.join(self.root, username))
                    session.add(user)
                    return user

                except Exception:
                    raise

    @login_required
    def auth_delete_user(self) -> None:
        """
        Delete the current user and all associated data.
        """
        with self.get_db_session() as session:
            if not self.current_user_id:
                raise AuthenticationError("User not logged in")

            try:
                with session.begin_nested():

                    # Delete owned files
                    owned_files = (
                        session.query(File)
                        .join(Ownership)
                        .join(AccessLevel)
                        .filter(
                            Ownership.user_id == self.current_user_id,
                        )
                        .filter(AccessLevel.is_original_creator.is_(True))
                        .all()
                    )

                for file in owned_files:
                    file_ownerships = (
                        session.query(Ownership)
                        .filter_by(file_id=file.id)
                        .all()
                    )

                    for ownership in file_ownerships:
                        session.delete(ownership.access_level)
                        session.delete(ownership)

                    with self._atomic_file_operation():
                        fs_path = self.path_ftp_to_fs(file.ftp_path)

                        if fs_path.exists():
                            if fs_path.is_dir():
                                shutil.rmtree(fs_path, ignore_errors=True)
                            else:
                                fs_path.unlink(missing_ok=True)

                    session.delete(file)

                # Delete remaining user ownerships
                remaining_ownerships = (
                    session.query(Ownership)
                    .filter_by(user_id=self.current_user_id)
                    .all()
                )

                for ownership in remaining_ownerships:
                    session.delete(ownership.access_level)
                    session.delete(ownership)

                # Delete user's root directory
                with self._atomic_file_operation():
                    user_root = self.root / self.current_username
                    if user_root.exists():
                        shutil.rmtree(user_root, ignore_errors=True)

                # Delete the user
                current_user = self.get_current_user(session)
                session.delete(current_user)
                self.auth_logout()

                self.logger.info(
                    "Successfully deleted user and \
                    all associated data"
                )

            except Exception as e:
                self.logger.error(f"Failed to delete user: {e}")
                raise

    def auth_user_exists(self, username: str) -> bool:
        """
        Check if a user exists.

        :param username: Username.
        :return: True if user exists, False otherwise.
        """
        return self.auth_get_username(username) is not None

    def auth_get_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.

        :param username: Username.
        :return: User object or None.
        """
        with self.get_db_session() as session:
            user = session.query(User).filter_by(username=username).first()
            username = user.username if user else None
            return username

    def auth_login(self, username: str, password: str) -> bool:
        """
        Log in a user.

        :param username: Username.
        :param password: Password.
        :return: True if login is successful, False otherwise.
        """
        try:
            with self.get_db_session() as session:
                user = session.query(User).filter_by(username=username).first()
                if user and user.authenticate(password):
                    self.current_user_id = user.id
                    self.current_ftp_dir = PurePath("/")
                    self.current_username = user.username
                    return True

                return False

        except Exception as e:
            self.logger.error(f"Login failed: {e}")
            return False

    def auth_logout(self) -> None:
        """
        Log out the current user.
        """
        self.current_ftp_dir = None
        self.current_username = None

    @login_required
    def auth_change_password(self, new_password: str) -> None:
        """
        Change the password of the current user.

        :param new_password: New password.
        """
        with self._user_ops_lock:
            with self.get_db_session() as session:
                user = self.get_current_user(session)
                user.password = User._hash_password(new_password)

    def path_ftp_to_fs(self, ftp_path: Union[str, PurePath], creator_username: str = None) -> Path:
        """
        Convert an FTP path to a filesystem path.

        :param ftp_path: FTP path.
        :return: Filesystem path.
        """
        if not self.current_username and not creator_username:
            raise AuthenticationError("No user logged in")

        if creator_username:
            username = creator_username
        
        else:
            username = self.current_username
        
        try:
            ftp_path = Path(str(ftp_path)).relative_to("/")
            # if ".." in str(ftp_path):
            #     raise ValueError("Path cannot contain ..")

            fs_path = (self.root / username / ftp_path).resolve()
            # user_root = (self.root / self.current_username).resolve()

            # if not fs_path.is_relative_to(user_root):
            #     raise ValueError("Access denied: Path outside user directory")

            return fs_path.resolve()

        except Exception as e:
            raise ValueError(f"Invalid path: {ftp_path}") from e

    def path_fs_to_ftp(self, fs_path: Union[str, Path], creator_username=None) -> PurePath:
        """
        Convert a filesystem path to an FTP path.

        :param fs_path: Filesystem path.
        :return: FTP path.
        """
        if not self.current_username and not creator_username:
            raise AuthenticationError("No user logged in")

        if creator_username:
            username = creator_username
        
        else:
            username = self.current_username

        try:
            fs_path = Path(str(fs_path)).resolve()
            user_root = (Path(self.root) / username).resolve()

            # if not fs_path.is_relative_to(user_root):
            #     raise ValueError("Access denied: Path outside user directory")

            ftp_path = PurePath(fs_path.relative_to(user_root))

            return PurePath("/") / ftp_path

        except Exception as e:
            raise ValueError(f"Invalid path: {fs_path}") from e

    @login_required
    def get_permission(self, ftp_path: PurePath) -> AccessLevel:
        """
        Get the access level for a given FTP path.

        :param ftp_path: FTP path.
        :return: Access level.
        """
        if not self.current_user_id:
            raise AuthenticationError("No user logged in")

        if str(ftp_path) == str(PurePath("/")):
            return AccessLevel(can_read=True, can_write=True, can_execute=True)

        with self.get_db_session() as session:
            # First, try to find a file owned by the current user
            file = (session.query(File)
                    .join(Ownership)
                    .join(AccessLevel)
                    .filter(Ownership.user_id == self.current_user_id)
                    .filter(File.ftp_path == str(ftp_path))
                    .filter(AccessLevel.is_original_creator.is_(True))
                    .first())

            # If no file is found, try to find a shared file
            if not file:
                file = (session.query(File)
                        .join(Ownership)
                        .join(AccessLevel)
                        .filter(File.ftp_path == str(ftp_path))
                        .first())

            if not file:
                raise FileNotFoundError(
                    f"File with path '{str(ftp_path)}' not found"
                )

            ownership = (
                session.query(Ownership)
                .filter_by(file_id=file.id, user_id=self.current_user_id)
                .first()
            )

            if not ownership:
                raise PermissionError("No permission for this file")

            session.refresh(ownership.access_level)

            return AccessLevel(
                can_read=ownership.access_level.can_read,
                can_write=ownership.access_level.can_write,
                can_execute=ownership.access_level.can_execute,
                is_original_creator=ownership.access_level.is_original_creator,
            )

    @login_required
    @resolve_path("ftp_path")
    def create_file(
        self, ftp_path: PurePath, anonymous_accesslevel: str = "---"
    ) -> str:
        """
        Create a new file.

        :param ftp_path: FTP path for the new file.
        :param anonymous_accesslevel: Access level for anonymous users.
        :return: Dictionary with file object and path.
        """
        if not is_valid_filename(ftp_path.name):
            raise ValueError("Invalid filename")

        # Check permissions for the parent dir
        if not self.get_permission(ftp_path.parent).can_write:
            raise PermissionError("No write permission")

        with self._atomic_file_operation():
            with self.get_db_session() as session:
                # Convert anonymous permissions to booleans
                (
                    ano_can_read,
                    ano_can_write,
                    ano_can_execute,
                ) = self.access_level_str_to_bools(anonymous_accesslevel)

                # Create file obj
                file = File(ftp_path=str(ftp_path), is_dir=False, creator_username=self.current_username)
                fs_path = self.path_ftp_to_fs(file.ftp_path)

                # Check if parent directory exists
                if not fs_path.parent.exists():
                    raise FileNotFoundError("Parent directory not found")

                # Check if file already exists
                if fs_path.exists():
                    raise FileExistsError("File already exists")

                # Set up permissions
                access_level = AccessLevel(
                    can_read=True,
                    can_write=True,
                    can_execute=True,
                    is_original_creator=True,
                )

                ownership = Ownership(
                    file=file,
                    owner=self.get_current_user(session),
                    access_level=access_level,
                )

                file.set_anonymous_access(
                    session,
                    can_read=ano_can_read,
                    can_write=ano_can_write,
                    can_execute=ano_can_execute,
                )

                session.add_all([file, access_level, ownership])

                # Create empty file
                fs_path.touch()

                return {"File": file, "path": str(fs_path)}

    @login_required
    @resolve_path("ftp_path")
    def delete_file(self, ftp_path: PurePath) -> None:
        """
        Delete a file.

        :param ftp_path: FTP path of the file to delete.
        """
        # Check permissions
        if not self.get_permission(ftp_path).can_write:
            raise PermissionError("No write permission")

        with self._atomic_file_operation():
            with self.get_db_session() as session:
                # Check if file exists
                file = (session.query(File)
                        .filter_by(ftp_path=str(ftp_path))
                        .first())

                if not file:
                    raise FileNotFoundError("File not found in database")

                fs_path = self.path_ftp_to_fs(file.ftp_path, creator_username=file.creator_username)

                if not fs_path.exists():
                    raise FileNotFoundError("File not found on the server")

                # Delete ownerships
                for ownership in file.ownerships:
                    session.delete(ownership.access_level)
                    session.delete(ownership)

                session.delete(file)

                # Delete file
                fs_path.unlink()

    @login_required
    @resolve_path("ftp_path")
    def read_file(self, ftp_path: PurePath) -> Dict[str, Union[File, Path]]:
        """
        Read a file.

        :param ftp_path: FTP path of the file to read.
        :return: Dictionary with file object and path.
        """
        # check permissions
        if not self.get_permission(ftp_path).can_read:
            raise PermissionError("No read permission")

        with self.get_db_session() as session:
            # check if file exists
            file = (session.query(File)
                    .filter_by(ftp_path=str(ftp_path))
                    .first())

            if not file:
                raise FileNotFoundError("File not found in database")

            fs_path = self.path_ftp_to_fs(file.ftp_path, creator_username=file.creator_username)

            if not fs_path.exists():
                raise FileNotFoundError(
                    f"File not found on the server, path: {fs_path}"
                )

            return {"File": file, "path": fs_path}

    @login_required
    @resolve_path("ftp_path")
    def mkdir(self, ftp_path: str, anonymous_accesslevel: str = "---") -> None:
        """
        Create a new directory.

        :param ftp_path: FTP path for the new directory.
        :param anonymous_accesslevel: Access level for anonymous users.
        """
        if not is_valid_filename(ftp_path.name):
            raise ValueError("Invalid directory name")

        # Check permissions for the parent dir
        if not self.get_permission(ftp_path.parent).can_write:
            raise PermissionError("No write permission")

        with self._atomic_file_operation():
            with self.get_db_session() as session:
                # Convert anonymous permissions to booleans
                (
                    ano_can_read,
                    ano_can_write,
                    ano_can_execute,
                ) = self.access_level_str_to_bools(anonymous_accesslevel)

                folder = File(ftp_path=str(ftp_path), is_dir=True, creator_username=self.current_username)
                fs_path = self.path_ftp_to_fs(folder.ftp_path)

                # check if parent directory exists
                if not fs_path.parent.exists():
                    raise FileNotFoundError("Parent directory not found")

                # check if directory already exists
                if fs_path.exists():
                    raise FileExistsError("Directory already exists")

                fs_path.mkdir()

                # set up permissions
                access_level = AccessLevel(
                    can_read=True,
                    can_write=True,
                    can_execute=True,
                    is_original_creator=True,
                )

                ownership = Ownership(
                    file=folder,
                    owner=self.get_current_user(session),
                    access_level=access_level,
                )

                folder.set_anonymous_access(
                    session,
                    can_read=ano_can_read,
                    can_write=ano_can_write,
                    can_execute=ano_can_execute,
                )

                session.add_all([folder, access_level, ownership])

    @login_required
    @resolve_path("ftp_path")
    def rmdir(self, ftp_path: str, require_empty: bool = False):
        """
        Remove a directory.

        :param ftp_path: FTP path of the directory to remove.
        :param require_empty: if the directory must be empty to be removed.
        """
        # Check permissions
        if not self.get_permission(ftp_path).can_write:
            raise PermissionError("No write permission")

        with self._atomic_file_operation():
            with self.get_db_session() as session:
                # Query DB
                folder = (
                    session.query(File)
                    .filter_by(ftp_path=str(ftp_path), is_dir=True)
                    .first()
                )

                if not folder:
                    raise FileNotFoundError("Directory not found in database")

                fs_path = self.path_ftp_to_fs(folder.ftp_path, creator_username=folder.creator_username)

                # check if directory exists
                if not fs_path.exists():
                    raise FileNotFoundError("Directory not found")

                # check if directory is empty
                is_empty = len(list(fs_path.iterdir())) == 0

                if require_empty and not is_empty:
                    raise ValueError("Directory is not empty")

                # delete db entry
                session.delete(folder)

                # delete directory
                if is_empty:
                    fs_path.rmdir()

                else:
                    shutil.rmtree(fs_path)

    @login_required
    @resolve_path("target_ftp_path")
    def change_dir(self, target_ftp_path: PurePath):
        """
        Change the current directory.

        :param target_ftp_path: Target FTP path to change to.
        """
        fs_path = self.path_ftp_to_fs(target_ftp_path)

        # resolve path (convert .. to absolute path)
        fs_path = fs_path.resolve()
        ftp_path = self.path_fs_to_ftp(fs_path)

        # check access
        if not self.get_permission(ftp_path).can_read:
            raise PermissionError("No read permission for this directory")

        # Check if directory exists
        if not fs_path.exists() or not fs_path.is_dir():
            raise FileNotFoundError(f"Directory not found: {target_ftp_path}")

        # Update current directory
        self.current_ftp_dir = ftp_path
        self.logger.info(f"Changed directory to {ftp_path}")

    @login_required
    @resolve_path("ftp_path")
    def _list_dir(
        self, ftp_path: PurePath, db_session: scoped_session
    ) -> List[File]:
        """
        List the contents of a directory.

        :param ftp_path: FTP path of the directory to list.
        :param db_session: Database session.
        :return: List of files in the directory.
        """
        current_username = self.current_username
        
        # Handle root
        if ftp_path == PurePath("/"):
            files = (
                db_session.query(
                    File,
                    (File.creator_username != self.current_username).label('is_shared')
                )
                .join(Ownership)
                .join(AccessLevel)
                .filter(Ownership.user_id == self.current_user_id)
                .filter(
                    or_(
                        # Only apply path filter for files user created
                        and_(
                            File.creator_username == current_username,
                            ~File.ftp_path.like(f"{PurePath('/')}%{PurePath('/')}%")
                        ),
                        # Show all shared files without path filter
                        File.creator_username != current_username
                    ))
                .filter(AccessLevel.can_read.is_(True))
                .all()
            )

        else:
            # add a slash at the end of the path
            if not str(ftp_path).endswith(str(PurePath("/"))):
                ftp_path: str = str(ftp_path) + str(PurePath("/"))

            files = (
                db_session.query(
                    File,
                    (File.creator_username != self.current_username).label('is_shared')
                )
                .join(Ownership)
                .join(AccessLevel)
                .filter(Ownership.user_id == self.current_user_id)
                .filter(File.creator_username == current_username)
                .filter(File.ftp_path.startswith(ftp_path))
                .filter(~File.ftp_path.like(f"{ftp_path}%{PurePath('/')}%"))
                .filter(AccessLevel.can_read.is_(True))
                .all()
            )

        return files

    @login_required
    @resolve_path("ftp_path")
    def list_dir(self, ftp_path: str = None) -> List[dict]:
        """
        List the contents of a directory in a human-readable format.

        :param ftp_path: FTP path of the directory to list.
        :return: List of dictionaries containing file information.
        """
        with self.get_db_session() as session:
            files = self._list_dir(ftp_path, db_session=session)
            file_list = []

            for file, is_shared in files:
                fs_path = self.path_ftp_to_fs(file.ftp_path, creator_username=file.creator_username)

                if not fs_path.exists():
                    self.logger.warning(
                        f"File with id {file.id} is in the database but not "
                        f"on the system, skipping"
                    )
                    continue

                stats = os.stat(fs_path)

                # Get permissions
                ownership = (
                    session.query(Ownership)
                    .filter_by(file_id=file.id, user_id=self.current_user_id)
                    .first()
                )

                perms = self.access_level_to_str(ownership.access_level)

                anonymous_perms = self.access_level_to_str(
                    file.anonymous_access
                )

                time_stamp = stats.st_mtime
                date = time.strftime("%b %d %H:%M", time.localtime(time_stamp))

                file_info = {
                    "type": "d" if file.is_dir else "-",
                    "permissions": perms * 2 + anonymous_perms,
                    "owner": self.current_username,
                    "group": self.current_username,
                    "size": stats.st_size,
                    "date": date,
                    "name": fs_path.name if not is_shared else file.ftp_path,
                }

                file_list.append(file_info)

            return file_list

    @login_required
    @resolve_path("ftp_path")
    def mlsd_dir(self, ftp_path: str = None) -> List[str]:
        """
        List the contents of a directory in MLSD format.

        :param ftp_path: FTP path of the directory to list.
        :return: List of strings containing file information in MLSD format.
        """

        def format_mlsd_time(timestamp: float) -> str:
            return time.strftime("%Y%m%d%H%M%S", time.gmtime(timestamp))

        def format_mlsd_perms(access_level) -> str:
            perms = []
            if access_level.can_read:
                perms.append("r")
            if access_level.can_write:
                perms.append("w")
            if access_level.can_write:
                perms.append("a")
            if access_level.can_write:
                perms.append("d")
            return "".join(perms)

        def format_mlsd_entry(file_obj, stats, perms) -> str:
            facts = [
                f"type={'dir' if file_obj.is_dir else 'file'}",
                f"size={stats.st_size}",
                f"modify={format_mlsd_time(stats.st_mtime)}",
                f"perms={format_mlsd_perms(perms)}",
            ]
            return f"{';'.join(facts)}; {PurePath(file_obj.ftp_path).name if not is_shared else file_obj.ftp_path}"

        with self.get_db_session() as session:
            files = self._list_dir(ftp_path, db_session=session)

            mlsd_list = []
            for file, is_shared in files:
                if not file:
                    continue
                fs_path = self.path_ftp_to_fs(file.ftp_path, creator_username=file.creator_username)

                if not fs_path.exists():
                    self.logger.warning(
                        f"File with id {file.id} is in the database but not "
                        f"on the system, skipping"
                    )
                    continue

                stats = os.stat(fs_path)
                ownership = (
                    session.query(Ownership)
                    .filter_by(file_id=file.id, user_id=self.current_user_id)
                    .first()
                )

                mlsd_entry = format_mlsd_entry(
                    file, stats, ownership.access_level
                )
                mlsd_list.append(mlsd_entry)

            return mlsd_list

    @login_required
    @resolve_path("ftp_path")
    def rename(self, ftp_path: PurePath, new_name: str) -> None:
        """
        Rename a file or directory.

        :param ftp_path: FTP path of the file or directory to rename.
        :param new_name: New name for the file or directory.
        """
        new_name = new_name.strip().strip("/")
        if "/" in new_name:
            new_name = new_name.split("/")[-1]
        
        elif "\\" in new_name:
            new_name = new_name.split("\\")[-1]
        
        # Check permissions
        if not self.get_permission(ftp_path).can_write:
            raise PermissionError("No write permission")

        with self._atomic_file_operation():
            with self.get_db_session() as session:
                # Query DB
                file = (session.query(File)
                        .filter_by(ftp_path=str(ftp_path))
                        .first())

                if not file:
                    raise FileNotFoundError("File not found in database")

                fs_path = self.path_ftp_to_fs(file.ftp_path, creator_username=file.creator_username)

                # Check if file exists
                if not fs_path.exists():
                    raise FileNotFoundError("File not found")

                # Rename file
                new_fs_path = fs_path.parent / new_name
                new_ftp_path = ftp_path.parent / new_name

                # Update path in db
                file.ftp_path = str(new_ftp_path)

                fs_path.rename(new_fs_path)

    @login_required
    @resolve_path("target_path")
    def chmod(
        self,
        target_path: str,
        target_username: str,
        permissions: str,
        public_permissions: str,
    ) -> None:
        """
        Change the permissions of a file or directory.

        :param target_path: FTP path of the file or directory.
        :param target_username: Username of the target user.
        :param permissions: Permissions for the target user.
        :param public_permissions: Permissions for anonymous users.
        """
        # check permissions
        if not self.get_permission(target_path).is_original_creator:
            raise PermissionError("No write permission")

        with self.get_db_session() as session:
            can_read, can_write, can_execute = self.access_level_str_to_bools(
                permissions
            )

            # get target user
            target_user = (
                session.query(User).filter_by(username=target_username).first()
            )

            if not target_user:
                raise ValueError("Target user not found")

            # get file
            file = (session.query(File)
                    .filter_by(ftp_path=str(target_path))
                    .first())

            if not file:
                raise FileNotFoundError("File not found")

            # get ownership
            current_ownership = (
                session.query(Ownership)
                .filter_by(file_id=file.id, user_id=target_user.id)
                .first()
            )

            if not current_ownership:
                # create a new ownership
                access_level = AccessLevel(
                    can_read=can_read,
                    can_write=can_write,
                    can_execute=can_execute
                )
                ownership = Ownership(
                    file=file,
                    owner=target_user,
                    access_level=access_level
                )

                session.add_all([access_level, ownership])

            else:
                # update the existing one
                current_ownership.access_level.can_read = can_read
                current_ownership.access_level.can_write = can_write
                current_ownership.access_level.can_execute = can_execute

                session.add(current_ownership.access_level)

            # update public permissions
            (
                public_can_read,
                public_can_write,
                public_can_execute,
            ) = self.access_level_str_to_bools(public_permissions)

            file.update_anonymous_access(
                session,
                can_read=public_can_read,
                can_write=public_can_write,
                can_execute=public_can_execute,
            )

    @staticmethod
    def access_level_to_str(access_level: AccessLevel) -> str:
        """
        Convert an AccessLevel object to a string representation.

        :param access_level: AccessLevel object.
        :return: String representation of the access level.
        """
        perms = "r" if access_level.can_read else "-"
        perms += "w" if access_level.can_write else "-"
        perms += "x" if access_level.can_execute else "-"

        return perms

    @staticmethod
    def access_level_str_to_bools(
        access_level_str: str
    ) -> Tuple[bool, bool, bool]:
        """
        Convert a string representation of access levels to booleans.

        :param access_level_str: String representation of access levels.
        :return: Tuple of booleans representing read, write, and execute
                 permissions.
        """
        assert (
            len(access_level_str) == 3
        ), "Access level string must be 3 characters long"

        return (
            access_level_str[0] == "r",
            access_level_str[1] == "w",
            access_level_str[2] == "x",
        )

    def __enter__(self):
        """
        Enter the runtime context related to this object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the runtime context related to this object.

        :param exc_type: Exception type.
        :param exc_val: Exception value.
        :param exc_tb: Traceback object.
        """
        self.Session.remove()
        self.engine.dispose()
