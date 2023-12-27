import asyncio
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from pathlib import Path
import shutil
from typing import Annotated
from uuid import UUID, uuid4
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.params import Body, Depends, Form
from fastapi.websockets import WebSocketState
import jwt
from pydantic import BaseModel, Field, FileUrl, JsonValue, model_validator

from .types import (
    Credentials,
    DeletionLog,
    FileObject,
    FileRemoteId,
    FileVersion,
    Graph,
    GraphEncryptKeys,
    GraphSalt,
    SimpleGraph,
    TempCredential,
    Transaction,
    TxId,
    UserInfo,
)
from . import db
from .db import get_db_session


logger = logging.getLogger(__name__)
app = FastAPI()

WS_BROADCAST: dict[str, set[WebSocket]] = defaultdict(set)
USER_UUID = str(UUID(bytes=b"ivan-123456789ab"))
S3_LOCAL_ROOT = Path("/tmp/s3proxy/logseq-file-sync-bucket")
# graph uuid -> [ws connection]


@app.get("/")
def root():
    return {"msg": "Logseq sync backend"}


@app.get("/logseq/version")
def version():
    return {}


@app.post("/oauth2/token")
def oauth_token(refresh_token: Annotated[str, Form()]):
    exp = datetime.now(timezone.utc) + timedelta(hours=2)  # at least 1h
    return {
        "id_token": jwt.encode(
            {
                "sub": USER_UUID,
                "email": "ivan@local.com",
                "exp": exp,
            },
            "secret",
            algorithm="HS256",
        ),
        "access_token": jwt.encode(
            {"some": "payload", "exp": exp},
            "secret",
            algorithm="HS256",
        ),
    }


async def broadcast_graph_change(uuid: str, new_txid: int):
    print(f"broadcasting graph change {uuid=} {new_txid=}")

    ws_cons = WS_BROADCAST.get(uuid)
    if not ws_cons:
        print(f"no ws cons registered for {uuid}!")
        return

    async with asyncio.TaskGroup() as tg:
        for ws in ws_cons:
            match ws.application_state:
                case WebSocketState.CONNECTED:
                    tg.create_task(ws.send_json({"txid": new_txid}))
                case WebSocketState.DISCONNECTED:
                    ws_cons.remove(ws)
                case WebSocketState.CONNECTING:
                    pass


@app.websocket("/file-sync")
async def ws_file_sync(ws: WebSocket, graphuuid: str):
    print(f"ws for {graphuuid}")
    # TODO: assert the graph exists
    await ws.accept()

    # when transaction for this graph, send {"txid": 99}
    WS_BROADCAST[graphuuid].add(ws)

    while True:
        try:
            data = await ws.receive_text()
        except WebSocketDisconnect:
            break

        match data:
            case "PING":
                await ws.send_text("PONG")
            case _:
                print(f"ws data: {data}")

    WS_BROADCAST[graphuuid].remove(ws)


@app.post("/file-sync/user_info")
def user_info() -> UserInfo:
    return UserInfo(
        groups=["alpha-tester", "beta-tester", "pro"],
        lemon_status="active",
        lemon_ends_at=datetime.now(timezone.utc) + timedelta(days=13),
        lemon_renews_at=datetime.now(timezone.utc) + timedelta(days=13),
    )


@app.post("/file-sync/get_temp_credential")
def get_temp_credential() -> TempCredential:
    """get temp credentials for uploading transactions

    aka upload file transaction

    used by rsapi refresh_temp_credential
    """
    # TODO: integrate s3 backend
    return TempCredential(
        credentials=Credentials(
            access_key_id="access-key-id-xxx",
            expiration=datetime.now(timezone.utc) + timedelta(days=7),
            secret_key="secret-key-xxx",
            session_token="session-token-xxx",
        ),
        s3_prefix=f"{USER_UUID}/staging",
    )


class CreateGraphInput(BaseModel):
    graph_name: str = Field(validation_alias="GraphName")


@app.post("/file-sync/create_graph", status_code=status.HTTP_201_CREATED)
def create_graph(
    input: CreateGraphInput, db_session: db.Session = Depends(get_db_session)
) -> SimpleGraph:
    with db_session.begin():
        db_graph = db.Graphs(name=input.graph_name, uuid=str(uuid4()))
        db_session.add(db_graph)
        db_session.flush()
        sgraph = SimpleGraph(name=db_graph.name, uuid=db_graph.uuid)

    return sgraph


class GetGraphByNameOrUIIDInput(BaseModel):
    graph_name: str | None = Field(None, validation_alias="GraphName")
    graph_uuid: str | None = Field(None, validation_alias="GraphUUID")

    @model_validator(mode="after")
    def check_name_or_uuid(self):
        if not (bool(self.graph_name) ^ bool(self.graph_uuid)):
            raise ValueError("either name or uuid is required but not both")
        return self


@app.post("/file-sync/get_graph")
def get_graph_by_name_or_uuid(
    input: GetGraphByNameOrUIIDInput,
    db_session: db.Session = Depends(get_db_session),
) -> Graph:
    """unused in src code"""
    filter_by = {}
    if input.graph_name:
        filter_by["name"] = input.graph_name
    if input.graph_uuid:
        filter_by["uuid"] = input.graph_uuid

    with db_session.begin():
        db_graph = db_session.query(db.Graphs).filter_by(**filter_by).one_or_none()
        graph = (
            Graph(
                name=db_graph.name,
                uuid=db_graph.uuid,
                txid=db_graph.current_txid,
                storage_usage=1313,
                storage_limit=4242,
            )
            if db_graph
            else None
        )

    if not graph:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return graph


class DeleteGraphInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/file-sync/delete_graph", status_code=status.HTTP_200_OK)
def delete_graph(
    input: DeleteGraphInput,
    db_session: db.Session = Depends(get_db_session),
):
    """returns 2xx if deletion went ok"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )

        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_session.delete(db_graph)


class GetGraphTxidInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


class GetGraphTxidOutput(BaseModel):
    txid: TxId


@app.post("/file-sync/get_txid")
def get_graph_txid(
    input: GetGraphTxidInput,
    db_session: db.Session = Depends(get_db_session),
) -> GetGraphTxidOutput:
    """returns the latest txid of the graph"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )

        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        current_txid = db_graph.current_txid

    return GetGraphTxidOutput(txid=current_txid)


class ListGraphsOutput(BaseModel):
    graphs: list[Graph] = Field(serialization_alias="Graphs")


@app.post("/file-sync/list_graphs")
def list_graphs(db_session: db.Session = Depends(get_db_session)) -> ListGraphsOutput:
    with db_session.begin():
        db_graphs = db_session.query(db.Graphs).all()
        graphs = [
            Graph(
                name=dbg.name,
                uuid=dbg.uuid,
                txid=dbg.current_txid,
                storage_usage=1313 * 1024 * 1024,
                storage_limit=4242 * 1024 * 1024,
            )
            for dbg in db_graphs
        ]

    return ListGraphsOutput(graphs=graphs)


class GetGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/file-sync/get_graph_salt")
def get_graph_salt(
    input: GetGraphSaltInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> GraphSalt:
    """get current graph passhprase salt

    return httpcode 410 when salt expired and generate a new one
    """

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        db_graph_id = db_graph.id

        db_graph_salt = (
            db_session.query(db.GraphSalts)
            .filter_by(graph_id=db_graph_id)
            .one_or_none()
        )
        graph_salt = (
            GraphSalt(
                value=db_graph_salt.value,
                expires_at=db_graph_salt.expires_at.replace(tzinfo=timezone.utc),
            )
            if db_graph_salt
            else None
        )

    if not graph_salt or graph_salt.is_expired:
        raise HTTPException(status_code=status.HTTP_410_GONE)

    return graph_salt


class CreateGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/file-sync/create_graph_salt", status_code=status.HTTP_201_CREATED)
def create_graph_salt(
    input: CreateGraphSaltInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> GraphSalt:
    """salt to use for graph passphrase storing. client will store it locally encrypted with this salt

    return httpcode 409 when salt already exists and not expired yet but still return it
    """

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_id = db_graph.id

        db_graph_salt = (
            db_session.query(db.GraphSalts)
            .filter_by(graph_id=db_graph_id)
            .one_or_none()
        )
        graph_salt = (
            GraphSalt.model_validate(db_graph_salt, from_attributes=True)
            if db_graph_salt
            else None
        )

    if graph_salt and not graph_salt.is_expired:
        response.status_code = status.HTTP_409_CONFLICT
        return graph_salt

    graph_salt = GraphSalt.create_random()

    with db_session.begin():
        db_session.add(
            db.GraphSalts(
                graph_id=db_graph_id,
                value=graph_salt.value,
                expires_at=graph_salt.expires_at,
            )
        )

    return graph_salt


class GetGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/file-sync/get_graph_encrypt_keys")
def get_graph_encrypt_keys(
    input: GetGraphEncryptKeysInput,
    db_session: db.Session = Depends(get_db_session),
) -> GraphEncryptKeys:
    """return 404 if keys doesn't exists"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_enckeys = (
            db_session.query(db.GraphEncryptionKeys)
            .filter_by(graph_id=db_graph.id)
            .one_or_none()
        )
        graph_enckeys = (
            GraphEncryptKeys.model_validate(db_graph_enckeys, from_attributes=True)
            if db_graph_enckeys
            else None
        )

    if not graph_enckeys:
        raise HTTPException(status_code=404)

    return graph_enckeys


class UploadGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    public_key: Annotated[
        GraphEncryptKeys.__annotations__["public_key"],
        Field(validation_alias="public-key"),
    ]
    encrypted_private_key: Annotated[
        GraphEncryptKeys.__annotations__["encrypted_private_key"],
        Field(validation_alias="encrypted-private-key"),
    ]


@app.post("/file-sync/upload_graph_encrypt_keys", status_code=status.HTTP_201_CREATED)
def upload_graph_encrypt_keys(
    input: UploadGraphEncryptKeysInput,
    db_session: db.Session = Depends(get_db_session),
):
    """return 2xx with no body"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_id = db_graph.id

        db_graph_enckeys = (
            db_session.query(db.GraphEncryptionKeys)
            .filter_by(graph_id=db_graph_id)
            .one_or_none()
        )

    if db_graph_enckeys:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT)

    with db_session.begin():
        db_session.add(
            db.GraphEncryptionKeys(
                graph_id=db_graph_id,
                public_key=input.public_key,
                encrypted_private_key=input.encrypted_private_key,
            )
        )


class UpdateFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: Annotated[TxId, Field(validation_alias="TXId")]
    files: dict[FileRemoteId, tuple[str, str]] = Field(
        validation_alias="Files",
        description=(
            "{ FileRemoteId: (TempRemotePath, MD5Checksum) }. "
            "the checksum is of the unencrypted content so the client will know when the file content changed. we can't use the encrypted content as it's salted"
        ),
        # { "encrypted_file_path": ("s3-prefix/<random>", "md5-checksum") }
    )


class UpdateFilesOutput(BaseModel):
    message: str | None = None
    txid: TxId
    suc_files: list[FileRemoteId] = Field(serialization_alias="UpdateSuccFiles")
    fail_files: dict[FileRemoteId, str] = Field(serialization_alias="UpdateFailedFiles")
    # ^^ {"fileremoteid": "idk"} TODO


@app.post("/file-sync/update_files")
async def update_files(
    input: UpdateFilesInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> UpdateFilesOutput:
    """move temp uploaded files into their permanent location

    aka commit file transaction

    main flow is in rsapi/update_remote_files

    Theoretically, the flow here is something like:
        1. calls get_temp_credential in refresh_temp_credential if needed
        2. calls upload_tempfile which PUTs some arbitrary number files to that location
            - this seems like an attack vector, but a short expiration should mitigate?
        3. calls this endpoint via update_files(encrypted_file_path, remote_temp_url, md5checksum)
        4. we move those files into their permanent locations by making a Transaction

    ref: https://github.com/bcspragu/logseq-sync
    """

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )

        if not db_graph:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="graph not found"
            )

        db_graph_id = db_graph.id
        db_graph_current_txid = db_graph.current_txid

    if db_graph_current_txid > input.txid:
        # TODO: trigger a websocket update txid event
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="outdated txn id")

    db_txn = db_session.begin()

    db_graph.current_txid += 1
    db_graph_current_txid = db_graph.current_txid

    transaction = db.Transactions(
        graph_id=db_graph_id, type="update_files", txid=db_graph.current_txid
    )
    db_session.add_all([db_graph, transaction])
    db_session.flush()

    suc_files = []
    fail_files = {}
    for fileid, (tmp_remote_path, md5_checksum) in input.files.items():
        # TODO: integrate s3 backend
        tmp_full_remote_path = S3_LOCAL_ROOT / tmp_remote_path
        perm_remote_path = S3_LOCAL_ROOT / f"{USER_UUID}/{input.graph_uuid}" / fileid

        print(f"trying to stage {tmp_full_remote_path} -> {perm_remote_path}")
        remote_size = tmp_full_remote_path.stat().st_size

        # if we already have that hash then dont change the file
        # client should assert this before
        if (
            db_file_metadata := db_session.query(db.FilesMetadata)
            .filter_by(graph_id=db_graph_id, file_id=fileid)
            .one_or_none()
        ):
            if db_file_metadata.checksum == md5_checksum:
                print(f"avoiding staging the same file: {fileid}")
                fail_files[fileid] = "file already commited before"
                continue

        perm_remote_path.parent.mkdir(exist_ok=True, parents=True)
        shutil.copy(tmp_full_remote_path, perm_remote_path)

        file_version = db.FilesVersions(
            file_id=fileid,
            version_uuid=str(uuid4()),
            created_at=datetime.now(timezone.utc),  # autogenerate todo remove
        )
        transaction_content = db.TransactionContent(
            txn_id=transaction.id,
            to_path=fileid,
            from_path=tmp_remote_path,
            checksum=md5_checksum,
        )
        file_metadata = db.FilesMetadata(
            graph_id=db_graph_id,
            file_id=fileid,
            last_modified=file_version.created_at,
            checksum=md5_checksum,
            size=remote_size,
        )
        db_session.merge(file_metadata)
        db_session.add_all([file_version, transaction_content])

        suc_files.append(fileid)

    if suc_files:
        # TODO: assert that we have a good new txid and others did not commited first so that they will have the same txid
        db_txn.commit()
        db_txn.close()
        asyncio.create_task(
            broadcast_graph_change(input.graph_uuid, db_graph_current_txid)
        )
    else:
        logger.error("no suc files")
        db_txn.rollback()

    return UpdateFilesOutput(
        txid=db_graph_current_txid, suc_files=suc_files, fail_files=fail_files
    )


class GetAllFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    # ContinuationToken: pagination cursor, first is None


class _AllFilesFileObject(FileObject):
    blob_path: Annotated[
        FileObject.__annotations__["blob_path"],
        Field(serialization_alias="Key"),
    ]


class GetAllFilesOutput(BaseModel):
    objects: list[_AllFilesFileObject] = Field(serialization_alias="Objects")
    # NextContinuationToken: pagination cursor


@app.post("/file-sync/get_all_files")
def get_all_files(
    input: GetAllFilesInput, db_session: db.Session = Depends(get_db_session)
) -> GetAllFilesOutput:
    """get initial metadata for files

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1253
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2786
    """
    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_files = (
            db_session.query(db.FilesMetadata).filter_by(graph_id=db_graph.id).all()
        )
        objects = [
            _AllFilesFileObject(
                blob_path=dbf.file_id,
                last_modified=dbf.last_modified.replace(tzinfo=timezone.utc),
                size=dbf.size,
                graph_txid=db_graph.current_txid,
                checksum=dbf.checksum,
            )
            for dbf in db_graph_files
        ]

    return GetAllFilesOutput(objects=objects)


class GetFilesMetaInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesMetaOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")


@app.post("/file-sync/get_files_meta")
def get_files_meta(
    input: GetFilesMetaInput, db_session: db.Session = Depends(get_db_session)
) -> list[FileObject]:
    """used to know if a file changed

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2529
    """
    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_files = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=db_graph.id)
            .where(db.FilesMetadata.file_id.in_(input.files))
            .all()
        )

        objects = [
            FileObject(
                blob_path=dbf.file_id,
                last_modified=dbf.last_modified.replace(tzinfo=timezone.utc),
                size=dbf.size,
                graph_txid=db_graph.current_txid,
                checksum=dbf.checksum,
            )
            for dbf in db_graph_files
        ]

    return objects


class GetFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesOutput(BaseModel):
    presigned_file_urls: dict[FileRemoteId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls"
    )


@app.post("/file-sync/get_files")
def get_files(
    input: GetFilesInput, db_session: db.Session = Depends(get_db_session)
) -> GetFilesOutput:
    """get presigned s3 urls for download

    called in rsapi/fetch_remote_files -> get_files(encrypted_paths)
    """

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_files = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=db_graph.id)
            .where(db.FilesMetadata.file_id.in_(input.files))
            .all()
        )

        fileids = set(dbf.file_id for dbf in db_graph_files)

    # TODO: presign urls

    return GetFilesOutput(
        presigned_file_urls={fileid: f"presigned-url/{fileid}" for fileid in fileids}
    )


class GetFileVersionListInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    file: FileRemoteId = Field(validation_alias="File")


class GetFileVersionListOutput(BaseModel):
    version_list: list[FileVersion] = Field(serialization_alias="VersionList")


@app.post("/file-sync/get_file_version_list")
def get_version_files(
    input: GetFileVersionListInput, db_session: db.Session = Depends(get_db_session)
) -> GetFileVersionListOutput:
    """get the list of versions for a file

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/handler/file_sync.cljs#L176
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/components/file_sync.cljs#L591
    """
    with db_session.begin():
        # file_id should not collide with anything so we are safe filtering only by that
        # TODO: use input.graph_uuid
        db_graph_version_files = (
            db_session.query(db.FilesVersions).filter_by(file_id=input.file).all()
        )

    return GetFileVersionListOutput(
        version_list=[
            FileVersion(
                create_time=dbvf.created_at,
                version_uuid=dbvf.version_uuid,
                file_uuid=dbvf.file_id,
            )
            for dbvf in db_graph_version_files
        ]
    )


FileVersionId = Annotated[str, Field(description="e.g. 'file-uuid/version-uuid'")]


class GetVersionFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileVersionId] = Field(validation_alias="Files")


class GetVersionFilesOutput(BaseModel):
    presigned_file_urls: dict[FileVersionId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls", description="urls for version-files"
    )


@app.post("/file-sync/get_version_files")
def get_version_files(
    input: GetVersionFilesInput, db_session: db.Session = Depends(get_db_session)
) -> GetVersionFilesOutput:
    """get a file version constructed from GetFileVersionListOutput

    call stack:

    <download-version-files graph-uuid base-path filepaths (in logseq/client)
    | call via rsapi/updateLocalVersionFiles
    update_local_version_files(base_path, file_paths, token) (in rsapi)
    get_version_files(file_paths)
    | call via post to this endpoint


    will be saved locally to 'logseq/version-files/file-uuid/version-uuid'


    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/handler/file_sync.cljs#L130
    """
    with db_session.begin():
        # file_id should not collide with anything so we are safe filtering only by that
        # TODO: use input.graph_uuid
        db_graph_version_files = (
            db_session.query(db.FilesVersions)
            .where(db.FilesVersions.file_id.in_(input.files))
            .all()
        )

    # TODO: presign urls

    return GetFilesOutput(
        presigned_file_urls={
            dbvf.file_id: f"presigned-url/version-files/{dbvf.file_id}/{dbvf.version_uuid}"
            for dbvf in db_graph_version_files
        }
    )


class DeleteFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    files: list[FileRemoteId] = Field(validation_alias="Files")


class DeleteFilesOutput(BaseModel):
    message: str | None = None
    txid: TxId
    suc_files: list[FileRemoteId] = Field(serialization_alias="DeleteSuccFiles")
    fail_files: dict[FileRemoteId, str] = Field(serialization_alias="DeleteFailedFiles")
    # ^^ {"fileremoteid": "idk"} TODO


@app.post("/file-sync/delete_files")
def delete_files(
    input: DeleteFilesInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> DeleteFilesOutput:
    """remove remote files

    called by rsapi/delete_remote_files
    """

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(uuid=input.graph_uuid).one_or_none()
        )
        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_graph_id = db_graph.id

    if db_graph.current_txid > input.txid:
        response.status_code = status.HTTP_410_GONE
        return {"message": "outdated txn id"}

    db_txn = db_session.begin()
    transaction = db.Transactions(graph_id=db_graph_id, type="delete_files")

    suc_files = []
    fail_files = {}
    for fileid in input.files:
        file_metadata = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=db_graph_id, file_id=fileid)
            .one_or_none()
        )

        if not file_metadata:
            fail_files[fileid] = "file not found"
            # TODO: try to delete in s3 any way
            continue

        # TODO: integrate s3 backend
        """
        s3_delete(fileid)
        """

        transaction_content = db.TransactionContent(
            txn_id=transaction.id,
            to_path=fileid,
            from_path=None,
            checksum=None,
        )

        db_session.add(transaction_content)
        db_session.delete(file_metadata)
        suc_files.append(fileid)

    if suc_files:
        db_graph.current_txid += 1
        transaction.txid = db_graph.current_txid
        db_session.add(db_graph)
        db_txn.close()
    else:
        db_txn.rollback()

    return DeleteFilesOutput(
        txid=db_graph.current_txid, suc_files=suc_files, fail_files=fail_files
    )


class GetDeletionLogsInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    from_txid: TxId = Field(validation_alias="FromTXId")


class GetDeletionLogsOutput(BaseModel):
    transactions: list[DeletionLog] = Field(serialization_alias="Transactions")


@app.post("/file-sync/get_deletion_log_v20221212")
def get_deletion_logs(
    input: GetDeletionLogsInput,
    db_session: db.Session = Depends(get_db_session),
) -> GetDeletionLogsOutput:
    """
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2788
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2597
    """

    with db_session.begin():
        deletion_txns = (
            db_session.query(db.Transactions)
            .filter_by(graph_id=input.graph_uuid, type="delete_files")
            .where(db.Transactions.txid >= input.from_txid)
            .join(db.TransactionContent)
            .all()
        )

    return GetDeletionLogsOutput(
        transactions=[
            DeletionLog(
                paths=[txn_content.to_path for txn_content in del_txn.content],
                txid=del_txn.txid,
                epoch=del_txn.created_at,
            )
            for del_txn in deletion_txns
        ]
    )


class TypicalResponse(BaseModel):
    message: str | None = None
    txid: TxId
    data: JsonValue | None = None
    # TODO: figure out how this ^^ is used. in rsapi it uses serde flatten so basically it means arbitrary data


class GetDiffInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    from_txid: TxId = Field(validation_alias="FromTXId")


class GetDiffOutput(TypicalResponse):
    transactions: list[Transaction] = Field(serialization_alias="Transactions")


@app.post("/file-sync/get_diff")
def get_diff(
    input: GetDiffInput, db_session: db.Session = Depends(get_db_session)
) -> GetDiffOutput:
    """get all transactions since from_txid

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1358

    used by smart merge in
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2450

    diff reference code: https://github.com/logseq/logseq/blob/master/src/main/frontend/fs/diff_merge.cljs
    """

    with db_session.begin():
        update_txns = (
            db_session.query(db.Transactions)
            .filter_by(graph_id=input.graph_uuid, type="update_files")
            .where(db.Transactions.txid >= input.from_txid)
            .join(db.TransactionContent)
            .all()
        )

    return GetDiffOutput(
        transactions=[
            Transaction(
                txid=upd_txn.txid,
                type="update_files",
                content=[
                    (txn_content.to_path, txn_content.from_path, txn_content.checksum)
                    for txn_content in upd_txn
                ],
            )
            for upd_txn in update_txns
        ],
    )


# --- unused in src code
class RenameFileInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    src_file: str = Field(validation_alias="SrcFile")
    dst_file: str = Field(validation_alias="DstFile")


class RenameFileOutput(TypicalResponse):
    pass


@app.post("/file-sync/rename_file")
def rename_file(input: RenameFileInput) -> RenameFileOutput:
    """
    called in rsapi rename_file
    """


# --- end


@app.api_route("/{full_path:path}", methods=["get", "post"])
async def catch_all(request: Request, full_path: str):
    print(f"++ unhandled request {request.method} at {full_path}")
    print(f"headers: {json.dumps(dict(request.headers))}")
    print(f"body: {await request.body()}")
    print("++")
