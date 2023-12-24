from datetime import datetime, timedelta
from typing import Annotated
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.params import Depends
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


app = FastAPI()


@app.get("/")
def root():
    return {"msg": "Logseq sync backend"}


@app.post("/user_info")
def user_info() -> UserInfo:
    return UserInfo(
        groups=["pro"],
        lemon_status="active",
        lemon_ends_at=datetime.utcnow() + timedelta(days=13),
        lemon_renews_at=datetime.utcnow() + timedelta(days=13),
    )


@app.post("/get_temp_credential")
def get_temp_credential() -> TempCredential:
    """get temp credentials for uploading transactions

    aka upload file transaction

    used by rsapi refresh_temp_credential
    """
    # TODO: integrate s3 backend
    return TempCredential(
        credentials=Credentials(
            access_key_id="access-key-id-xxx",
            expiration=datetime.utcnow() + timedelta(days=7),
            secret_key="secret-key-xxx",
            session_token="session-token-xxx",
        )
    )


class CreateGraphInput(BaseModel):
    graph_name: str = Field(validation_alias="GraphName")


@app.post("/create_graph", status_code=status.HTTP_201_CREATED)
def create_graph(
    input: CreateGraphInput, db_session: db.Session = Depends(get_db_session)
) -> SimpleGraph:
    with db_session.begin():
        db_graph = db.Graphs(name=input.graph_name)
        db_session.add(db_graph)
        db_session.flush()
        sgraph = SimpleGraph(name=db_graph.name, uuid=str(db_graph.id))

    return sgraph


class GetGraphByNameOrUIIDInput(BaseModel):
    graph_name: str | None = Field(None, validation_alias="GraphName")
    graph_uuid: str | None = Field(None, validation_alias="GraphUUID")

    @model_validator(mode="after")
    def check_name_or_uuid(self):
        if not (bool(self.graph_name) ^ bool(self.graph_uuid)):
            raise ValueError("either name or uuid is required but not both")
        return self


@app.post("/get_graph")
def get_graph_by_name_or_uuid(
    input: GetGraphByNameOrUIIDInput,
    db_session: db.Session = Depends(get_db_session),
) -> Graph:
    """unused in src code"""
    filter_by = {}
    if input.graph_name:
        filter_by["name"] = input.graph_name
    if input.graph_uuid:
        filter_by["id"] = input.graph_uuid

    with db_session.begin():
        db_graph = db_session.query(db.Graphs).filter_by(**filter_by).one_or_none()
        graph = (
            Graph(
                name=db_graph.name,
                uuid=str(db_graph.id),
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


@app.post("/delete_graph", status_code=status.HTTP_200_OK)
def delete_graph(
    input: DeleteGraphInput,
    db_session: db.Session = Depends(get_db_session),
):
    """returns 2xx if deletion went ok"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(id=input.graph_uuid).one_or_none()
        )

        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        db_session.delete(db_graph)


class GetGraphTxidInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


class GetGraphTxidOutput(BaseModel):
    txid: TxId


@app.post("/get_txid")
def get_graph_txid(
    input: GetGraphTxidInput,
    db_session: db.Session = Depends(get_db_session),
) -> GetGraphTxidOutput:
    """returns the latest txid of the graph"""

    with db_session.begin():
        db_graph = (
            db_session.query(db.Graphs).filter_by(id=input.graph_uuid).one_or_none()
        )

        if not db_graph:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        current_txid = db_graph.current_txid

    return GetGraphTxidOutput(txid=current_txid)


class ListGraphsOutput(BaseModel):
    graphs: list[Graph] = Field(serialization_alias="Graphs")


@app.post("/list_graphs")
def list_graphs(db_session: db.Session = Depends(get_db_session)) -> ListGraphsOutput:
    with db_session.begin():
        db_graphs = db_session.query(db.Graphs).all()
        graphs = [
            Graph(
                name=dbg.name,
                uuid=str(dbg.id),
                txid=dbg.current_txid,
                storage_usage=1313,
                storage_limit=4242,
            )
            for dbg in db_graphs
        ]

    return ListGraphsOutput(graphs=graphs)


class GetGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/get_graph_salt")
def get_graph_salt(
    input: GetGraphSaltInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> GraphSalt:
    """get current graph passhprase salt

    return httpcode 410 when salt expired and generate a new one
    """

    with db_session.begin():
        db_graph_salt = (
            db_session.query(db.GraphSalts)
            .filter_by(graph_id=input.graph_uuid)
            .one_or_none()
        )
        graph_salt = (
            GraphSalt.model_validate(db_graph_salt, from_attributes=True)
            if db_graph_salt
            else None
        )

    if graph_salt and not graph_salt.is_expired:
        return graph_salt

    # needs rotation
    response.status_code = status.HTTP_410_GONE

    graph_salt = GraphSalt.create_random()

    with db_session.begin():
        db_session.add(
            db.GraphSalts(
                graph_id=input.graph_uuid,
                value=graph_salt.value,
                expires_at=graph_salt.expires_at,
            )
        )

    return graph_salt


class CreateGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/create_graph_salt", status_code=status.HTTP_201_CREATED)
def create_graph_salt(
    input: CreateGraphSaltInput,
    response: Response,
    db_session: db.Session = Depends(get_db_session),
) -> GraphSalt:
    """salt to use for graph passphrase storing. client will store it locally encrypted with this salt

    return httpcode 409 when salt already exists and not expired yet but still return it
    """

    with db_session.begin():
        db_graph_salt = (
            db_session.query(db.GraphSalts)
            .filter_by(graph_id=input.graph_uuid)
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
                graph_id=input.graph_uuid,
                value=graph_salt.value,
                expires_at=graph_salt.expires_at,
            )
        )

    return graph_salt


class GetGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/get_graph_encrypt_keys")
def get_graph_encrypt_keys(
    input: GetGraphEncryptKeysInput,
    db_session: db.Session = Depends(get_db_session),
) -> GraphEncryptKeys:
    """return 404 if keys doesn't exists"""

    with db_session.begin():
        db_graph_enckeys = (
            db_session.query(db.GraphEncryptionKeys)
            .filter_by(graph_id=input.graph_uuid)
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


@app.post("/upload_graph_encrypt_keys", status_code=status.HTTP_201_CREATED)
def upload_graph_encrypt_keys(
    input: UploadGraphEncryptKeysInput,
    db_session: db.Session = Depends(get_db_session),
):
    """return 2xx with no body"""

    with db_session.begin():
        db_graph_enckeys = (
            db_session.query(db.GraphEncryptionKeys)
            .filter_by(graph_id=input.graph_uuid)
            .one_or_none()
        )

    if db_graph_enckeys:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT)

    with db_session.begin():
        db_session.add(
            db.GraphEncryptionKeys(
                graph_id=input.graph_uuid,
                public_key=input.public_key,
                encrypted_private_key=input.encrypted_private_key,
            )
        )


class UpdateFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    files: dict[FileRemoteId, tuple[str, str]] = Field(
        validation_alias="Files",
        description="{ FileRemoteId: (TempRemotePath, MD5Checksum) }",
        # { "encrypted_file_path": ("s3-prefix/<random>", "md5-checksum") }
    )


class UpdateFilesOutput(BaseModel):
    message: str | None = None
    txid: TxId
    suc_files: list[FileRemoteId] = Field(serialization_alias="UpdateSuccFiles")
    fail_files: dict[FileRemoteId, str] = Field(serialization_alias="UpdateFailedFiles")
    # ^^ {"fileremoteid": "idk"} TODO


@app.post("/update_files")
def update_files(
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
            db_session.query(db.Graphs).filter_by(id=input.graph_uuid).one_or_none()
        )

    if not db_graph:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "graph not found"}

    if db_graph.current_txid > input.txid:
        response.status_code = status.HTTP_410_GONE
        return {"message": "outdated txn id"}

    db_txn = db_session.begin()
    transaction = db.Transactions(graph_id=input.graph_uuid, type="update_files")

    suc_files = []
    fail_files = {}
    for fileid, (tmp_remote_path, md5_checksum) in input.files.items():
        # TODO: integrate s3 backend
        """
        remote_checksum = s3_get_checksum(tmp_remote_path)
        if remote_checksum != md5_checksum:
            fail_files[fileid] = "md5 checksum mismatch"
            continue

        remote_size = s3_get_size(tmp_remote_path)

        s3_move(tmp_remote_path, fileid)
        """

        file_version = db.FilesVersions(file_id=fileid)
        transaction_content = db.TransactionContent(
            txn_id=transaction.id,
            to_path=fileid,
            from_path=tmp_remote_path,
            checksum=md5_checksum,
        )
        file_metadata = db.FilesMetadata(
            graph_id=input.graph_uuid,
            file_id=fileid,
            last_modified=file_version.created_at,
            size=4242,
        )

        db_session.add_all([file_version, transaction_content, file_metadata])

        suc_files.append(fileid)

    if suc_files:
        db_graph.current_txid += 1
        transaction.txid = db_graph.current_txid
        db_session.add(db_graph)
        db_txn.close()
    else:
        db_txn.rollback()

    return UpdateFilesOutput(
        txid=db_graph.current_txid, suc_files=suc_files, fail_files=fail_files
    )


class GetAllFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    # ContinuationToken: pagination cursor, first is None


class GetAllFilesOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")
    # NextContinuationToken: pagination cursor


@app.post("/get_all_files")
def get_all_files(
    input: GetAllFilesInput, db_session: db.Session = Depends(get_db_session)
) -> GetAllFilesOutput:
    """get initial metadata for files

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1253
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2786
    """
    with db_session.begin():
        db_graph_files = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=input.graph_uuid)
            .all()
        )

    return GetAllFilesOutput(
        objects=[
            FileObject(
                key=dbf.file_id,
                last_modified=dbf.last_modified,
                size=dbf.size,
            )
            for dbf in db_graph_files
        ]
    )


class GetFilesMetaInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesMetaOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")


@app.post("/get_files_meta")
def get_files_meta(
    input: GetFilesMetaInput, db_session: db.Session = Depends(get_db_session)
) -> GetFilesMetaOutput:
    """used to know if a file changed

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2529
    """
    with db_session.begin():
        db_graph_files = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=input.graph_uuid)
            .where(db.FilesMetadata.file_id.in_(input.files))
            .all()
        )

    return GetFilesMetaOutput(
        objects=[
            FileObject(
                key=dbf.file_id,
                last_modified=dbf.last_modified,
                size=dbf.size,
            )
            for dbf in db_graph_files
        ]
    )


class GetFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesOutput(BaseModel):
    presigned_file_urls: dict[FileRemoteId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls"
    )


@app.post("/get_files")
def get_files(
    input: GetFilesInput, db_session: db.Session = Depends(get_db_session)
) -> GetFilesOutput:
    """get presigned s3 urls for download

    called in rsapi/fetch_remote_files -> get_files(encrypted_paths)
    """

    with db_session.begin():
        db_graph_files = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=input.graph_uuid)
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


@app.post("/get_file_version_list")
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
                version_uuid=dbvf.version_id,
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


@app.post("/get_version_files")
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
            dbvf.file_id: f"presigned-url/version-files/{dbvf.file_id}/{dbvf.version_id}"
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


@app.post("/delete_files")
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
            db_session.query(db.Graphs).filter_by(id=input.graph_uuid).one_or_none()
        )

    if not db_graph:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "graph not found"}

    if db_graph.current_txid > input.txid:
        response.status_code = status.HTTP_410_GONE
        return {"message": "outdated txn id"}

    db_txn = db_session.begin()
    transaction = db.Transactions(graph_id=input.graph_uuid, type="delete_files")

    suc_files = []
    fail_files = {}
    for fileid in input.files:
        file_metadata = (
            db_session.query(db.FilesMetadata)
            .filter_by(graph_id=input.graph_uuid, file_id=fileid)
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


@app.post("/get_deletion_log_v20221212")
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


@app.post("/get_diff")
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


@app.post("/rename_file")
def rename_file(input: RenameFileInput) -> RenameFileOutput:
    """
    called in rsapi rename_file
    """


# --- end
