all content-type=application/octet-stream

type Graph
    message: str | None
    StorageUsage: int
    TXId: int  # uint
    GraphName: str
    GraphUUID: str

type SimpleGraph
    GraphName: str
    GraphUUID: str

type FileObject
    ETag: str
    Key: str
    LastModified: datetime  # utc
    Size: int

type TempCredential
    Credentials: Credentials
    S3Prefix: str

type Credentials
    AccessKeyId: str
    Expiration: datetime # utc
    SecretKey: str
    SessionToken: str

type UpdateFiles
    message: str | None
    TXId: int  # uint
    UpdateSuccFiles: list[str]
    UpdateFailedFiles: {"fileid": "idk"}

type DeleteFiles
    message: str | None
    TXId: int  # uint
    DeleteSuccFiles: list[str]
    DeleteFailedFiles: {"fileid": "idk"}

type TypicalResponse
    message: str | None
    TXId: int  # uint
    data: serde_json::Value


POST /create_graph
    body: { "GraphName": name }
    res: Graph
    

POST /get_graph
    # get graph by name
    body: { "GraphName": name }
    res: Graph

    # get graph by uuid
    body: { "GraphUUID": graph_uuid }
    res: Graph

POST /list_graphs
    body: <empty>
    res: { "Graphs": [SimpleGraph] }
    

POST /get_all_files
    body: { "GraphUUID": graph_uuid }
    res: { "Objects" : [FileObject]}

POST /get_files
    body: {
        "GraphUUID": graph_uuid,
        "Files": ["file1", "file2"]
    }
    res: {
        "PresignedFileUrls" : {
            "file1": "presignedurl_file1"
        }
    }

POST /get_version_files
    body: {
        "GraphUUID": self.graph_uuid,
        "Files": ["file1", "file2"]
    }
    res: {
        "PresignedFileUrls": {
            "file1": "presignedurl_file1"
        }
    }

POST /get_temp_credential
    body: <empty>
    res: TempCredential

# -- start s3
GET <presignedurl>

PUT <presignurl>
    body: file stream
# -- end s3

POST /update_files
    body: {
        "GraphUUID": graph_uuid,
        "TXId": txid,
        "Files": files  
        # ^^ (key, value, checksum) => (page/page1.md, s3-prefix/xxxxxxxxxxx, md5-checksum)
    }
    res: UpdateFiles

POST /delete_files
    body: {
        "GraphUUID": graph_uuid,
        "TXId": txid,
        "Files": ["file1", "file2"]
    }
    res: DeleteFiles

POST /get_diff
    body: {
        "GraphUUID": graph_uuid,
        "FromTXId": txid0
    }
    res: TypicalResponse

POST /rename_file
    body: {
        "GraphUUID": graph_uuid,
        "TXId": txid,
        "SrcFile": from,
        "DstFile": to,
    }
    res: TypicalResponse



(smart merge)
diff reference code: https://github.com/logseq/logseq/blob/master/src/main/frontend/fs/diff_merge.cljs
sync reference code: https://github.com/logseq/logseq/blob/master/src/main/frontend/fs/sync.cljs
