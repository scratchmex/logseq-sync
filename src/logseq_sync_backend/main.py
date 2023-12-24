from datetime import datetime
from typing import Annotated
from fastapi import FastAPI
from pydantic import BaseModel, Field, FileUrl, JsonValue


# --- types
TxId = Annotated[int, Field(serialization_alias="TXId", ge=0)]
FileId = Annotated[
    str, Field(description="file id is the local file path. e.g. 'page/page1.md'")
]
# TODO: review all usage of this ^^ because remote should not know about original name
FileRemoteId = Annotated[
    str,
    Field(
        description="file remote id is the s3 file path (encrypted). e.g. 's3-prefix/xxxxxxxxxxx'"
    ),
]


class Graph(BaseModel):
    message: str | None = None
    storage_usage: int = Field(serialization_alias="StorageUsage")
    txid: TxId
    name: str = Field(serialization_alias="GraphName")
    uuid: str = Field(serialization_alias="GraphUUID")


class SimpleGraph(BaseModel):
    name: str = Field(serialization_alias="GraphName")
    uuid: str = Field(serialization_alias="GraphUUID")


class FileObject(BaseModel):
    etag: str = Field(serialization_alias="ETag")
    key: FileRemoteId = Field(serialization_alias="Key")
    last_modified: datetime = Field(serialization_alias="LastModified")  # utc
    size: int = Field(serialization_alias="Size")


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


class CreateGraphInput(BaseModel):
    graph_name: str = Field(validation_alias="GraphName")


@app.post("/user_info")
def user_info():
    pass


@app.post("/create_graph")
def create_graph(input: CreateGraphInput) -> Graph:
    return


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


class DeleteGraphInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


# TODO
class DeleteGraphOutput(BaseModel):
    pass


@app.post("/delete_graph")
def delete_graph(input: DeleteGraphInput) -> DeleteGraphOutput:
    pass


class GetGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


# TODO
class GetGraphSaltOutput(BaseModel):
    pass


@app.post("/get_graph_salt")
def get_graph_salt(input: GetGraphSaltInput) -> GetGraphSaltOutput:
    pass


class CreateGraphSaltInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


# TODO
class CreateGraphSaltOutput(BaseModel):
    pass


@app.post("/create_graph_salt")
def create_graph_salt(input: CreateGraphSaltInput) -> CreateGraphSaltOutput:
    pass


class GetGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


# TODO
class GetGraphEncryptKeysOutput(BaseModel):
    pass


@app.post("/get_graph_encrypt_keys")
def get_graph_encrypt_keys(
    input: GetGraphEncryptKeysInput,
) -> GetGraphEncryptKeysOutput:
    pass


class UploadGraphEncryptKeysInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    public_key: str = Field(validation_alias="public-key")
    encrypted_private_key: str = Field(validation_alias="encrypted-private-key")


# TODO
class UploadGraphEncryptKeysOutput(BaseModel):
    pass


@app.post("/upload_graph_encrypt_keys")
def upload_graph_encrypt_keys(
    input: UploadGraphEncryptKeysInput,
) -> UploadGraphEncryptKeysOutput:
    pass


class GetGraphTxidInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


class GetGraphTxidOutput(BaseModel):
    txid: TxId


@app.post("/get_txid")
def get_graph_txid(input: GetGraphTxidInput) -> GetGraphTxidOutput:
    return


class ListGraphsOutput(BaseModel):
    graphs: list[SimpleGraph] = Field(serialization_alias="Graphs")


@app.post("/list_graphs")
def list_graphs() -> ListGraphsOutput:
    return


class GetAllFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")


class GetAllFilesOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")


@app.post("/get_all_files")
def get_all_files(input: GetAllFilesInput) -> GetAllFilesOutput:
    return


class GetFilesMetaInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesMetaOutput(BaseModel):
    objects: list[FileObject] = Field(serialization_alias="Objects")


@app.post("/get_files_meta")
def get_files_meta(input: GetFilesMetaInput) -> GetFilesMetaOutput:
    return


class GetFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetFilesOutput(BaseModel):
    presigned_file_urls: dict[FileRemoteId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls"
    )


@app.post("/get_files")
def get_files(input: GetFilesInput) -> GetFilesOutput:
    return


class GetVersionFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: list[FileRemoteId] = Field(validation_alias="Files")


class GetVersionFilesOutput(BaseModel):
    presigned_file_urls: dict[FileRemoteId, FileUrl] = Field(
        serialization_alias="PresignedFileUrls", description="urls for version-files"
    )


@app.post("/get_version_files")
def get_version_files(input: GetVersionFilesInput) -> GetVersionFilesOutput:
    return


class GetFileVersionListInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    files: FileRemoteId = Field(validation_alias="File")


class GetFileVersionListOutput(BaseModel):
    pass
    # TODO


@app.post("/get_file_version_list")
def get_version_files(input: GetFileVersionListInput) -> GetFileVersionListOutput:
    return


# TODO
@app.post("/get_deletion_log_v20221212")
def get_deletion_log_v20221212():
    pass


@app.post("/get_temp_credential")
def get_temp_credential() -> TempCredential:
    return


class UpdateFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    files: dict[FileId, tuple[FileRemoteId, str]] = Field(validation_alias="Files")
    # { key: (value, checksum) }
    # { "page/page1.md": ("s3-prefix/xxxxxxxxxxx", "md5-checksum") }


class UpdateFilesOutput(BaseModel):
    message: str | None = None
    txid: TxId
    suc_files: list[FileId] = Field(serialization_alias="UpdateSuccFiles")
    fail_files: dict[FileId, str] = Field(serialization_alias="UpdateFailedFiles")
    # ^^ {"fileid": "idk"} TODO


@app.post("/update_files")
def update_files(input: UpdateFilesInput) -> UpdateFilesOutput:
    return UpdateFilesOutput()


class DeleteFilesInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    files: list[FileRemoteId] = Field(validation_alias="Files")


class DeleteFilesOutput(BaseModel):
    message: str | None = None
    txid: TxId
    suc_files: list[FileId] = Field(serialization_alias="DeleteSuccFiles")
    fail_files: dict[FileId, str] = Field(serialization_alias="DeleteFailedFiles")
    # ^^ {"fileid": "idk"} TODO


@app.post("/delete_files")
def delete_files(input: DeleteFilesInput) -> DeleteFilesOutput:
    return DeleteFilesOutput()


class TypicalResponse(BaseModel):
    message: str | None = None
    txid: TxId
    data: JsonValue


class GetDiffInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    from_txid: TxId = Field(validation_alias="FromTXId")


class GetDiffOutput(TypicalResponse):
    pass


@app.post("/get_diff")
def get_diff(input: GetDiffInput) -> GetDiffOutput:
    """

    used by smart merge

    diff reference code: https://github.com/logseq/logseq/blob/master/src/main/frontend/fs/diff_merge.cljs
    """
    return


class RenameFileInput(BaseModel):
    graph_uuid: str = Field(validation_alias="GraphUUID")
    txid: TxId
    src_file: str = Field(validation_alias="SrcFile")
    dst_file: str = Field(validation_alias="DstFile")


class RenameFileOutput(TypicalResponse):
    pass


@app.post("/rename_file")
def rename_file(input: RenameFileInput) -> RenameFileOutput:
    return
