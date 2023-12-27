from contextlib import contextmanager
from datetime import datetime, timezone
from sqlalchemy import Column, ForeignKey, create_engine, schema, sql, types
from sqlalchemy.orm import sessionmaker, Session, declarative_base


SQLALCHEMY_DATABASE_URL = "sqlite:///./db.sqlite"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, autobegin=False, bind=engine
)
Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Graphs(Base):
    __tablename__ = "graphs"

    id = Column(types.Integer(), primary_key=True)
    uuid = Column(types.String(), nullable=False, unique=True)
    name = Column(types.String(), nullable=False, unique=True)
    current_txid = Column(types.Integer(), nullable=False, default=0)


class GraphSalts(Base):
    __tablename__ = "graph_salts"

    id = Column(types.Integer(), primary_key=True)
    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"))
    value = Column(types.String(), nullable=False)
    expires_at = Column(types.DateTime(timezone=True), nullable=False)


class GraphEncryptionKeys(Base):
    __tablename__ = "graph_encryption_keys"

    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"), primary_key=True)
    public_key = Column(types.String(), nullable=False)
    encrypted_private_key = Column(types.String(), nullable=False)


class Transactions(Base):
    __tablename__ = "transactions"

    id = Column(types.Integer(), primary_key=True)
    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"))
    txid = Column(types.Integer(), nullable=False)
    type = Column(types.String(), nullable=False)

    created_at = Column(types.DateTime(timezone=True), default=utcnow)


class TransactionContent(Base):
    __tablename__ = "transactions_content"

    id = Column(types.Integer(), primary_key=True)
    txn_id = Column(ForeignKey("transactions.id", ondelete="CASCADE"), nullable=False)
    to_path = Column(types.String(), nullable=False)
    from_path = Column(types.String(), nullable=True)
    checksum = Column(types.String(), nullable=True)


class FilesMetadata(Base):
    __tablename__ = "files_metadata"

    file_id = Column(types.String(), primary_key=True)
    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"))
    last_modified = Column(types.DateTime(timezone=True), nullable=False)
    size = Column(types.Integer(), nullable=False)
    checksum = Column(types.String(), nullable=False)


class FilesVersions(Base):
    __tablename__ = "files_versions"

    file_id = Column(
        ForeignKey("files_metadata.file_id", ondelete="CASCADE"), primary_key=True
    )
    version_uuid = Column(types.String(), primary_key=True, unique=True)

    created_at = Column(types.DateTime(timezone=True), nullable=False, default=utcnow)


def create_database_tables():
    Base.metadata.create_all(bind=engine)


def get_db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


db_session = contextmanager(get_db_session)


create_database_tables()
