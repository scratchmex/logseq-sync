# logseq sync backend

stack: fastapi and sqlalchemy

refer to [bcspragu/logseq-sync](https://github.com/bcspragu/logseq-sync) for other impl and more info (he did the first work and I heavily inspired on it)

# todo

the backend is in working state with the corresponding changes in rsapi and logseq itself. we only need a way to authenticate and actually integrate s3 backend

# dev

dependent on changes in [rsapi](https://github.com/logseq/rsapi/compare/master...scratchmex:rsapi:master) and [logseq](https://github.com/logseq/logseq/compare/master...scratchmex:logseq:master) (click to see changes on my forks)

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

set the local endpoint

<img width="594" alt="image" src="https://github.com/scratchmex/logseq-sync/assets/4014888/05c7f9e7-3e27-4d71-a508-550642d7245d">

and run `make dev` here

# spec

TODO architecture diagram


main files that use this:

- `logseq/src/main/frontend/fs/sync.cljs`: `IRSAPI` is for functions that call `rsapi` and `IRemoteAPI` consumes this api directly
- `logseq/src/main/frontend/{handler/file_sync.cljs,components/file_sync.cljs}`: UI elements for syncing
- `logseq/src/main/frontend/handler/events.cljs`: search for `file-sync` events
- `logseq/src/main/frontend/state.cljs`: global state where we save the custom endpoint
- `logseq/src/main/frontend/handler/user.cljs`: sync account/auth related
