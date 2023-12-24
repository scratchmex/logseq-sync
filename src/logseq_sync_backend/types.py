from typing import Annotated, Literal

from datetime import datetime
from pydantic import BaseModel, Field


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
