import base64
import hashlib
import secrets
from typing import Annotated, Literal

from datetime import datetime, timedelta, timezone
from pydantic import UUID4, AwareDatetime, BaseModel, Field, computed_field


TxId = Annotated[int, Field(serialization_alias="TXId", ge=0)]
FileRemoteId = Annotated[
    str,
    Field(
        description="file remote id is the s3 file encrypted (obfuscated) path. e.g. 'pages/contents.md' -> 'e.xxxxxx'"
    ),
]


class Graph(BaseModel):
    message: str | None = None
    name: Annotated[str, Field(serialization_alias="GraphName")]
    uuid: Annotated[UUID4, Field(serialization_alias="GraphUUID")]
    txid: TxId
    storage_usage: Annotated[
        int, Field(serialization_alias="GraphStorageUsage", description="in bytes")
    ]
    storage_limit: Annotated[
        int, Field(serialization_alias="GraphStorageLimit", description="in bytes")
    ]


class SimpleGraph(BaseModel):
    name: Annotated[str, Field(serialization_alias="GraphName")]
    uuid: Annotated[UUID4, Field(serialization_alias="GraphUUID")]


class GraphSalt(BaseModel):
    value: Annotated[str, Field(description="64-byte base64 salt")]
    expires_at: Annotated[
        AwareDatetime,
        Field(
            serialization_alias="expired-at", description="unix timestamp milliseconds"
        ),
    ]

    @classmethod
    def create_random(cls):
        return cls(
            value=base64.b64encode(secrets.token_bytes(64)),
            expires_at=datetime.now(timezone.utc) + timedelta(weeks=8),
        )

    @property
    def is_expired(self):
        return self.expires_at <= datetime.now(timezone.utc)


class GraphEncryptKeys(BaseModel):
    """ref: https://github.com/FiloSottile/age"""

    public_key: Annotated[
        str,
        Field(
            serialization_alias="public-key",
            description="age public key like 'agexxxx'",
        ),
    ]
    encrypted_private_key: Annotated[
        str,
        Field(
            serialization_alias="encrypted-private-key",
            description="age passphrase-encrypted private key which when decrypted will be something like 'AGE-SECRET-KEY-XXX'",
        ),
    ]


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
    type: Annotated[
        Literal["update_files", "delete_files", "rename_file"],
        Field(serialization_alias="TXType"),
    ]
    # ^^ ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L115
    content: list[TxOp]


class FileObject(BaseModel):
    blob_path: Annotated[
        FileRemoteId,
        Field(
            serialization_alias="FilePath",
            description="should be 'user-uuid/graph-uuid/e.encrypted-filename'. "
            'in files meta it should be "FilePath" and in all files "Key", wtf?',
        ),
    ]
    last_modified: Annotated[
        AwareDatetime, Field(serialization_alias="LastModified")
    ]  # utc
    size: Annotated[int, Field(serialization_alias="Size")]
    graph_txid: Annotated[
        TxId, Field(serialization_alias="Txid")
    ]  # << what is with these names? TXId, Txid, txid ...
    checksum: Annotated[
        str,
        Field(
            serialization_alias="Checksum",
            description="md5. in files meta it should be 'Checksum' and in all files 'checksum'",
        ),
    ]


class FileVersion(BaseModel):
    """used to list version files in order to later download them

    used to construct FileVersionId like 'file-uuid/version-uuid'
    """

    create_time: Annotated[AwareDatetime, Field(serialization_alias="CreateTime")]
    # ^^ or create-time (which is used in client src code)
    version_uuid: Annotated[UUID4, Field(serialization_alias="VersionUUID")]
    file_uuid: Annotated[UUID4, Field(serialization_alias="FileUUID")]


class DeletionLog(BaseModel):
    paths: list[FileRemoteId]
    # compared with FileMetadata.path got from <get-remote-all-files-meta (/get_all_files) and then decrypting. it looks like its comparing against non-encrypted path but the backend doesn't know anything about local paths so.. these are the to-path of Transaction
    # ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/fs/sync.cljs#L1275
    txid: TxId
    epoch: Annotated[
        int,
        Field(
            description="unix epoch. will be used to compare with FileMeta.last_modified"
        ),
    ]


class Credentials(BaseModel):
    access_key_id: Annotated[str, Field(serialization_alias="AccessKeyId")]
    expiration: Annotated[AwareDatetime, Field(serialization_alias="Expiration")]  # utc
    secret_key: Annotated[str, Field(serialization_alias="SecretKey")]
    session_token: Annotated[str, Field(serialization_alias="SessionToken")]


class TempCredential(BaseModel):
    credentials: Annotated[Credentials, Field(serialization_alias="Credentials")]
    s3_prefix: Annotated[
        str,
        Field(
            serialization_alias="S3Prefix",
            description="can be 'user-uuid/graph-uuid/tmp-path' ",
        ),
    ]


class UserInfo(BaseModel):
    groups: Annotated[
        list[Literal["pro", "alpha-tester", "beta-tester"]],
        Field(serialization_alias="UserGroups"),
    ]
    lemon_status: Annotated[
        Literal["active", "on_trial", "cancelled"],
        Field(serialization_alias="LemonStatus"),
    ]
    lemon_ends_at: Annotated[AwareDatetime, Field(serialization_alias="LemonEndsAt")]
    lemon_renews_at: Annotated[
        AwareDatetime, Field(serialization_alias="LemonRenewsAt")
    ]
    # -- undocumented props
    # ExpireTime: used to check if beta is available
    # ^^ ref: https://github.com/logseq/logseq/blob/981b1ef80f13ff2a88d663307a8cd111eecc2554/src/main/frontend/components/file_sync.cljs#L739
    # ProUser: bool
    # StorageLimit: int
    # GraphCountLimit: int
