from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from sqlalchemy import desc

from .db import (EndpointModel, FileEventModel, NetworkEventModel,
                 ProcessEventModel, Base, engine, get_session)

app = FastAPI(title="EDR Mock API (CrowdStrike Falcon-shaped)", version="0.1.0")

SEED = 42


@app.on_event("startup")
def _startup():
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(engine)
    session = get_session()
    try:
        if session.query(EndpointModel).count() == 0:
            from apis.edr.data_generator import generate_value
            value = generate_value(SEED)
            session.add_all(value["endpoints"])
            session.add_all(value["processes"])
            session.add_all(value["networks"])
            session.add_all(value["files"])
            session.commit()
    finally:
        session.close()


def _row_to_dict(row) -> dict:
    return {c.name: (getattr(row, c.name).isoformat()
                     if isinstance(getattr(row, c.name), datetime)
                     else getattr(row, c.name))
            for c in row.__table__.columns}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/endpoints")
def list_endpoints():
    session = get_session()
    try:
        return [_row_to_dict(e) for e in session.query(EndpointModel).all()]
    finally:
        session.close()


@app.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str):
    session = get_session()
    try:
        ep = session.query(EndpointModel).get(endpoint_id)
        if not ep:
            raise HTTPException(status_code=404, detail="endpoint not found")
        return _row_to_dict(ep)
    finally:
        session.close()


def _since_event(model_cls, query, since):
    if since:
        query = query.filter(model_cls.ts >= since)
    return query


@app.get("/endpoints/{endpoint_id}/processes")
def endpoint_processes(endpoint_id: str,
                       limit: int = Query(200, le=1000),
                       since: Optional[datetime] = None):
    session = get_session()
    try:
        q = session.query(ProcessEventModel).filter(
            ProcessEventModel.endpoint_id == endpoint_id)
        q = _since_event(ProcessEventModel, q, since)
        rows = q.order_by(desc(ProcessEventModel.ts)).limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()


@app.get("/endpoints/{endpoint_id}/network")
def endpoint_network(endpoint_id: str,
                     limit: int = Query(200, le=1000),
                     since: Optional[datetime] = None):
    session = get_session()
    try:
        q = session.query(NetworkEventModel).filter(
            NetworkEventModel.endpoint_id == endpoint_id)
        q = _since_event(NetworkEventModel, q, since)
        rows = q.order_by(desc(NetworkEventModel.ts)).limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()


@app.get("/endpoints/{endpoint_id}/files")
def endpoint_files(endpoint_id: str,
                   limit: int = Query(200, le=1000),
                   since: Optional[datetime] = None):
    session = get_session()
    try:
        q = session.query(FileEventModel).filter(
            FileEventModel.endpoint_id == endpoint_id)
        q = _since_event(FileEventModel, q, since)
        rows = q.order_by(desc(FileEventModel.ts)).limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()