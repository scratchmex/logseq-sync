from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest


from logseq_sync.main import app
from logseq_sync import db, types


@pytest.fixture(autouse=True)
def drop_data():
    with db.db_session() as db_session, db_session.begin():
        for table in db.Base.metadata.tables.values():
            db_session.execute(table.delete())


client = TestClient(app)


def test_root():
    res = client.get("/")
    assert res.status_code == 200

    res = client.get("/logseq/version")
    assert res.status_code == 200


def test_user_info():
    res = client.post("/file-sync/user_info")

    data = res.json()

    assert data["LemonStatus"] == "active"


def test_create_get_delete_list_graph():
    graph_name = "mygraph"

    res = client.post("/file-sync/create_graph", json={"GraphName": graph_name})
    data = res.json()
    graph_uuid = data["GraphUUID"]

    assert res.status_code == 201

    res = client.post("/file-sync/get_graph", json={"GraphName": graph_name})
    assert res.status_code == 200

    res = client.post("/file-sync/get_graph", json={"GraphUUID": graph_uuid})
    assert res.status_code == 200

    res = client.post("/file-sync/get_txid", json={"GraphUUID": graph_uuid})
    data = res.json()
    assert data["TXId"] == 0
    assert res.status_code == 200

    res = client.post("/file-sync/list_graphs")
    assert res.json()["Graphs"]
    assert res.status_code == 200

    res = client.post("/file-sync/delete_graph", json={"GraphUUID": graph_uuid})
    assert res.status_code == 200

    res = client.post("/file-sync/get_graph", json={"GraphUUID": graph_uuid})
    assert res.status_code == 404


def test_create_get_salt():
    graph_name = "mygraph"

    res = client.post("/file-sync/create_graph", json={"GraphName": graph_name})
    graph_uuid = res.json()["GraphUUID"]

    res = client.post("/file-sync/create_graph_salt", json={"GraphUUID": graph_uuid})
    assert res.status_code == 201

    res = client.post("/file-sync/get_graph_salt", json={"GraphUUID": graph_uuid})
    assert res.status_code == 200

    res = client.post("/file-sync/create_graph_salt", json={"GraphUUID": graph_uuid})
    assert res.status_code == 409

    # expire salt

    with db.db_session() as db_session, db_session.begin():
        db_graph = db_session.query(db.Graphs).filter_by(uuid=graph_uuid).one()
        db_graphsalt = (
            db_session.query(db.GraphSalts).filter_by(graph_id=db_graph.id).one()
        )
        db_graphsalt.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.add(db_graphsalt)
        prev_salt = db_graphsalt.value

    res = client.post("/file-sync/get_graph_salt", json={"GraphUUID": graph_uuid})
    new_salt = res.json()["value"]
    assert new_salt != prev_salt
    assert res.status_code == 410


def test_create_get_graph_encrypt_keys():
    graph_name = "mygraph"

    res = client.post("/file-sync/create_graph", json={"GraphName": graph_name})
    graph_uuid = res.json()["GraphUUID"]

    res = client.post(
        "/file-sync/get_graph_encrypt_keys", json={"GraphUUID": graph_uuid}
    )
    assert res.status_code == 404

    res = client.post(
        "/file-sync/upload_graph_encrypt_keys",
        json={
            "GraphUUID": graph_uuid,
            "public-key": "agexxxx",
            "encrypted-private-key": "AGE-SECRET-KEY-XXX",
        },
    )
    assert res.status_code == 201

    res = client.post(
        "/file-sync/upload_graph_encrypt_keys",
        json={
            "GraphUUID": graph_uuid,
            "public-key": "agexxxx-nope",
            "encrypted-private-key": "AGE-SECRET-KEY-XXX-nope",
        },
    )
    assert res.status_code == 409

    res = client.post(
        "/file-sync/get_graph_encrypt_keys", json={"GraphUUID": graph_uuid}
    )
    data = res.json()
    assert "nope" not in data["public-key"]
    assert "age" in data["public-key"]
    assert "nope" not in data["encrypted-private-key"]
    assert "AGE-SECRET-KEY" in data["encrypted-private-key"]
    assert res.status_code == 200
