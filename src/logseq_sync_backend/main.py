from datetime import datetime
from typing import Annotated, Literal
from fastapi import FastAPI
from pydantic import BaseModel, Field, FileUrl, JsonValue


# --- types
TxId = Annotated[int, Field(serialization_alias="TXId", ge=0)]
FileRemoteId = Annotated[
    str,
    Field(
        description="file remote id is the s3 file encrypted (obfuscated) path. e.g. 'pages/contents.md' -> 'e.xxxxxx'"
    ),
]


class Graph(BaseModel):
    message: str | None = None
    name: str = Field(serialization_alias="GraphName")
    uuid: str = Field(serialization_alias="GraphUUID")
    txid: TxId
    storage_usage: int = Field(serialization_alias="GraphStorageUsage")
    storage_limit: int = Field(serialization_alias="GraphStorageLimit")


class SimpleGraph(BaseModel):
    name: str = Field(serialization_alias="GraphName")
    uuid: str = Field(serialization_alias="GraphUUID")


class GraphSalt(BaseModel):
    value: str = Field(description="64-byte base64 salt")
    expired_at: int = Field(
        serialization_alias="expired-at", description="unix timestamp milliseconds"
    )


class GraphEncryptKeys(BaseModel):
    """ref: https://github.com/FiloSottile/age"""

    public_key: str = Field(
        serialization_alias="public-key", description="age public key"
    )
    encrypted_private_key: str = Field(
        serialization_alias="encrypted-private-key",
        description="age passphrase-encrypted private key which when decrypted will be something like 'AGE-SECRET-KEY-XXX'",
    )


TxOp = Annotated[
    tuple[str, str, str],
    Field(
        serialization_alias="TXContent",
        description="(FileRemoteId, TempRemotePath, MD5Checksum)",
        # ^^ to-path from-path checksum
        # ^^ when txn type is deletion the to-path is the actual deleted path and the other fields are null
    ),
    # path in transactions can skip s3 prefix of graph-uuid and user-uuid
    # ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1359
]


class Transaction(BaseModel):
    txid: TxId
    type: Literal["update_files", "delete_files", "rename_file"] = Field(
        serialization_alias="TXType"
    )
    # ^^ ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L115
    content: list[TxOp]


class FileObject(BaseModel):
    etag: str = Field(serialization_alias="ETag")
    key: FileRemoteId = Field(serialization_alias="Key")
    last_modified: datetime = Field(serialization_alias="LastModified")  # utc
    size: int = Field(serialization_alias="Size")


class FileVersion(BaseModel):
    """used to list version files in order to later download them

    used to construct FileVersionId like 'file-uuid/version-uuid'
    """

    create_time: datetime = Field(serialization_alias="CreateTime")
    # ^^ or create-time (which is used in client src code)
    version_uuid: str = Field(serialization_alias="VersionUUID")
    file_uuid: str = Field(serialization_alias="FileUUID")


class DeletionLog(BaseModel):
    paths: list[FileRemoteId]
    # compared with FileMetadata.path got from <get-remote-all-files-meta (/get_all_files) and then decrypting. it looks like its comparing against non-encrypted path but the backend doesn't know anything about local paths so.. these are the to-path of Transaction
    # ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1275
    txid: TxId
    epoch: int = Field(
        description="unix epoch. will be used to compare with FileMeta.last_modified"
    )


class Credentials(BaseModel):
    access_key_id: str = Field(serialization_alias="AccessKeyId")
    expiration: datetime = Field(serialization_alias="Expiration")  # utc
    secret_key: str = Field(serialization_alias="SecretKey")
    session_token: str = Field(serialization_alias="SessionToken")


class TempCredential(BaseModel):
    credentials: Credentials = Field(serialization_alias="Credentials")
    s3_prefix: str = Field(serialization_alias="S3Prefix")


# --- api

app = FastAPI()


@app.get("/")
def root():
    return {"msg": "Logseq sync backend"}


class UserInfo(BaseModel):
    groups: list[Literal["pro"]] = Field(serialization_alias="UserGroups")
    lemon_status: Literal["active", "on_trial", "cancelled"] = Field(
        serialization_alias="LemonStatus"
    )
    lemon_ends_at: datetime = Field(serialization_alias="LemonEndsAt")
    lemon_renews_at: datetime = Field(serialization_alias="LemonRenewsAt")
    # -- undocumented props
    # ExpireTime: used to check if beta is available
    # ^^ ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/components/file_sync.cljs#L739
    # ProUser: bool
    # StorageLimit: int
    # GraphCountLimit: int


@app.post("/user_info")
def user_info() -> UserInfo:
    pass


class CreateGraphInput(BaseModel):
    graph_name: str = Field(validation_alias="GraphName")


@app.post("/create_graph")
def create_graph(input: CreateGraphInput) -> SimpleGraph:
    return


# --- unused in src code
class GetGraphByNameInput(BaseModel):
    graph_name: str = Field(validation_alias="GraphName")


@app.post("/get_graph")
def get_graph_by_name(input: GetGraphByNameInput) -> Graph:
    return


class GetGraphByUUIDInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/get_graph")
def get_graph_by_uuid(input: GetGraphByUUIDInput) -> Graph:
    return


# --- end


class DeleteGraphInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/delete_graph")
def delete_graph(input: DeleteGraphInput):
    """returns 200 if deletion went ok"""


class GetGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/get_graph_salt")
def get_graph_salt(input: GetGraphSaltInput) -> GraphSalt:
    """get current graph passhprase salt

    return httpcode 410 when salt expired and generate a new one
    """


class CreateGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/create_graph_salt")
def create_graph_salt(input: CreateGraphSaltInput) -> GraphSalt:
    """salt to use for graph passphrase storing. client will store it locally encrypted with this salt

    return httpcode 409 when salt already exists and not expired yet but still return it
    """


class GetGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/get_graph_encrypt_keys")
def get_graph_encrypt_keys(input: GetGraphEncryptKeysInput) -> GraphEncryptKeys:
    """return 404 if keys doesn't exists"""


class UploadGraphEncryptKeysInput(GraphSalt):
    graph_uuid: str = Field(validation_alias="GraphUUID")


@app.post("/upload_graph_encrypt_keys")
def upload_graph_encrypt_keys(input: UploadGraphEncryptKeysInput):
    """return 200 with no body"""


class GetGraphTxidInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


class GetGraphTxidOutput(BaseModel):
    txid: TxId


@app.post("/get_txid")
def get_graph_txid(input: GetGraphTxidInput) -> GetGraphTxidOutput:
    """returns the latest txid of the graph"""


class ListGraphsOutput(BaseModel):
    graphs: list[Graph] = Field(serialization_alias="Graphs")


@app.post("/list_graphs")
def list_graphs() -> ListGraphsOutput:
    return


class GetAllFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    # ContinuationToken: pagination cursor, first is None


class GetAllFilesOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")
    # NextContinuationToken: pagination cursor


@app.post("/get_all_files")
def get_all_files(input: GetAllFilesInput) -> GetAllFilesOutput:
    """get initial metadata for files

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1253
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2786
    """


class GetFilesMetaInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesMetaOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")


@app.post("/get_files_meta")
def get_files_meta(input: GetFilesMetaInput) -> GetFilesMetaOutput:
    """used to know if a file changed

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2529
    """


class GetFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesOutput(BaseModel):
    presigned_file_urls: dict[FileRemoteId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls"
    )


@app.post("/get_files")
def get_files(input: GetFilesInput) -> GetFilesOutput:
    """get presigned s3 urls for download

    called in rsapi/fetch_remote_files -> get_files(encrypted_paths)
    """


class GetFileVersionListInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    file: FileRemoteId = Field(validation_alias="File")


class GetFileVersionListOutput(BaseModel):
    version_list: list[FileVersion] = Field(serialization_alias="VersionList")


@app.post("/get_file_version_list")
def get_version_files(input: GetFileVersionListInput) -> GetFileVersionListOutput:
    """get the list of versions for a file

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/handler/file_sync.cljs#L176
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/components/file_sync.cljs#L591
    """


FileVersionId = Annotated[str, Field(description="e.g. 'file-uuid/version-uuid'")]


class GetVersionFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileVersionId] = Field(validation_alias="Files")


class GetVersionFilesOutput(BaseModel):
    presigned_file_urls: dict[FileVersionId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls", description="urls for version-files"
    )


@app.post("/get_version_files")
def get_version_files(input: GetVersionFilesInput) -> GetVersionFilesOutput:
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


class GetDeletionLogsInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    from_txid: TxId = Field(validation_alias="FromTXId")


class GetDeletionLogsOutput(BaseModel):
    transactions: list[DeletionLog] = Field(serialization_alias="Transactions")


@app.post("/get_deletion_log_v20221212")
def get_deletion_logs(input: GetDeletionLogsInput) -> GetDeletionLogsOutput:
    """
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2788
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2597
    """


@app.post("/get_temp_credential")
def get_temp_credential() -> TempCredential:
    """get temp credentials for uploading transactions

    aka upload file transaction

    used by rsapi refresh_temp_credential
    """


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
def update_files(input: UpdateFilesInput) -> UpdateFilesOutput:
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
def delete_files(input: DeleteFilesInput) -> DeleteFilesOutput:
    """remove remote files

    called by rsapi/delete_remote_files
    """


class TypicalResponse(BaseModel):
    message: str | None = None
    txid: TxId
    data: JsonValue


class GetDiffInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    from_txid: TxId = Field(validation_alias="FromTXId")


class GetDiffOutput(TypicalResponse):
    transactions: list[Transaction] = Field(serialization_alias="Transactions")


@app.post("/get_diff")
def get_diff(input: GetDiffInput) -> GetDiffOutput:
    """get all transactions since from_txid

    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1358

    used by smart merge in
    ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L2450

    diff reference code: https://github.com/logseq/logseq/blob/master/src/main/frontend/fs/diff_merge.cljs
    """


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
