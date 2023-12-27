# logseq sync backend

stack: fastapi and sqlalchemy

refer to [bcspragu/logseq-sync](https://github.com/bcspragu/logseq-sync) for other impl and more info (he did the first work and I heavily inspired on it)

# dev

link the rsapi project with the logseq with

```
ln -sf ~/code/rsapi/packages/rsapi/rsapi.darwin-arm64.node ~/code/logseq/static/node_modules/@logseq/rsapi-darwin-arm64
```

and run `yarn watch` in the rsapi project

run s3-proxy to have a local s3 with your filesystem `s3proxy --properties s3proxy.conf`

```
// s3proxy.conf
s3proxy.authorization=none
s3proxy.endpoint=http://127.0.0.1:8080
jclouds.provider=filesystem
jclouds.filesystem.basedir=/tmp/s3proxy
```

run logseq develop as usual

```
yarn watch
yarn dev-electron-app
```

and set the local endpoint



# spec

TODO architecture diagram


main files that use this:

- `logseq/src/main/frontend/fs/sync.cljs`: `IRSAPI` is for functions that call `rsapi` and `IRemoteAPI` consumes this api directly
- `logseq/src/main/frontend/{handler/file_sync.cljs,components/file_sync.cljs}`: UI elements for syncing
- `logseq/src/main/frontend/handler/events.cljs`: search for `file-sync` events
- `logseq/src/main/frontend/state.cljs`: global state where we save the custom endpoint
- `logseq/src/main/frontend/handler/user.cljs`: sync account/auth related
