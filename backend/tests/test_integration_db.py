"""Integration tests: simulator <-> database, engines <-> persisted history, transactions."""

import pytest
from sqlalchemy import func, select

from app.engines import analysis
from app.services import env_store, sim_service
from app.sim_models import (
    SimAuditEvent, SimCostDaily, SimFinding, SimMetric, SimRecommendation, SimRelationship, SimResource, SimScan,
)
from app.simulator import lifecycle, timeengine
from app.simulator.env import SimError
from app.simulator.generator import generate_environment
from app.simulator.config import SimConfig


@pytest.fixture()
def stored(db):
    env = generate_environment(SimConfig(seed=11))
    row = env_store.create_environment(db, env, "integration")
    db.commit()
    return db, row, env


def test_environment_round_trips_through_the_database_unchanged(stored):
    db, row, env = stored
    loaded = env_store.load(db, row)
    assert loaded.fingerprint() == env.fingerprint()                      # resources, metrics and costs identical
    assert loaded.baseline is not None and loaded.config == env.config
    assert loaded.id_counters == env.id_counters


def test_relationships_and_inventory_rows_match_the_model(stored):
    db, row, env = stored
    assert db.scalar(select(func.count()).select_from(SimResource).where(SimResource.environment_id == row.id)) == sum(len(v) for v in env.resources.values())
    rels = db.scalar(select(func.count()).select_from(SimRelationship).where(SimRelationship.environment_id == row.id))
    from app.simulator.env import relationships
    assert rels == len(relationships(env)) > 50
    types = {t for (t,) in db.execute(select(SimResource.resource_type).where(SimResource.environment_id == row.id).distinct())}
    assert {"vpc", "subnet", "ec2_instance", "s3_bucket", "rds_instance", "iam_role", "security_group"} <= types


def test_save_applies_only_changes_and_history_is_append_only(stored):
    db, row, _ = stored
    env = env_store.load(db, row)
    metrics_before = db.scalar(select(func.count()).select_from(SimMetric))
    costs_before = db.scalar(select(func.count()).select_from(SimCostDaily))
    first_ids = {i for (i,) in db.execute(select(SimMetric.id).limit(50))}
    timeengine.advance(env, 2)
    env_store.save(db, row, env, row.state_version)
    db.commit()
    assert db.scalar(select(func.count()).select_from(SimMetric)) > metrics_before
    assert db.scalar(select(func.count()).select_from(SimCostDaily)) > costs_before
    assert first_ids <= {i for (i,) in db.execute(select(SimMetric.id))}   # old rows untouched
    reloaded = env_store.load(db, db.get(type(row), row.id))
    assert reloaded.fingerprint() == env.fingerprint() and reloaded.sim_time == env.sim_time


def test_lifecycle_changes_persist_and_deleted_resources_disappear_from_inventory(stored):
    db, row, _ = stored
    env = env_store.load(db, row, history=False)
    vol = next(v for v in env.of("ebs_volume") if v["state"] == "available")
    lifecycle.execute(env, "ebs.delete", vol["id"], {})
    new_bucket = lifecycle.execute(env, "s3.create_bucket", None, {"name": "acme-persisted"})["created"][0]
    env_store.save(db, row, env, row.state_version)
    db.commit()
    ids = {r for (r,) in db.execute(select(SimResource.resource_id).where(SimResource.environment_id == row.id))}
    assert vol["id"] not in ids and new_bucket in ids


def test_optimistic_locking_rejects_a_stale_writer(stored):
    db, row, _ = stored
    a, b = env_store.load(db, row, history=False), env_store.load(db, row, history=False)
    version = row.state_version
    lifecycle.execute(a, "eip.allocate", None, {})
    lifecycle.execute(b, "eip.allocate", None, {})
    env_store.save(db, row, a, version)
    db.commit()
    with pytest.raises(SimError) as exc:
        env_store.save(db, db.get(type(row), row.id), b, version)
    assert exc.value.code == "conflict" and exc.value.status == 409
    db.rollback()
    assert db.get(type(row), row.id).state_version == version + 1


def test_failed_mutation_rolls_back_and_leaves_database_untouched(stored):
    db, row, _ = stored
    before = db.scalar(select(func.count()).select_from(SimResource))
    version = db.get(type(row), row.id).state_version

    def explode(env):
        lifecycle.execute(env, "eip.allocate", None, {})
        raise SimError("boom", "invalid_operation", 409)

    with pytest.raises(SimError):
        sim_service.mutate(db, "tester", "ACTION:test", explode)
    assert db.scalar(select(func.count()).select_from(SimResource)) == before
    assert db.get(type(row), row.id).state_version == version
    rejected = db.scalar(select(func.count()).select_from(SimAuditEvent).where(SimAuditEvent.outcome == "REJECTED"))
    assert rejected == 1                                                     # the failed attempt is still recorded


def test_scan_persists_findings_recommendations_and_reconciles_history(stored):
    db, row, _ = stored
    env = env_store.load(db, row)
    from app.services.scan import run_scan
    scan1, res1 = run_scan(db, row, env, trigger="manual", actor="t")
    db.commit()
    assert db.scalar(select(func.count()).select_from(SimFinding).where(SimFinding.status == "OPEN")) == len(res1["findings"])
    assert db.scalar(select(func.count()).select_from(SimRecommendation)) == len(res1["recommendations"])
    scan_again, _ = run_scan(db, row, env, trigger="manual", actor="t")
    db.commit()
    assert scan_again.new_findings == 0 and scan_again.resolved_findings == 0     # idempotent for an unchanged environment
    assert db.scalar(select(func.count()).select_from(SimFinding)) == len(res1["findings"])  # no duplicates
    some = db.execute(select(SimFinding).where(SimFinding.first_scan_id == scan1.id)).scalars().first()
    assert some.last_scan_id == scan_again.id and some.first_seen_sim == some.last_seen_sim


def test_findings_resolve_in_database_only_when_condition_disappears(stored):
    db, row, _ = stored
    from app.services.scan import run_scan
    env = env_store.load(db, row)
    run_scan(db, row, env, trigger="manual", actor="t")
    db.commit()
    target = db.execute(select(SimFinding).where(SimFinding.rule_id == "S3-001")).scalars().first()
    if target is None:                                                       # seed 11 may not expose a bucket: create the condition
        bucket = env.of("s3_bucket")[0]
        lifecycle.execute(env, "s3.set_public_access_block", bucket["id"], {"block": False})
        lifecycle.execute(env, "s3.set_acl", bucket["id"], {"acl": "public-read"})
        run_scan(db, row, env, trigger="manual", actor="t")
        db.commit()
        target = db.execute(select(SimFinding).where(SimFinding.rule_id == "S3-001")).scalars().first()
    assert target.status == "OPEN"
    run_scan(db, row, env, trigger="manual", actor="t")
    db.commit()
    assert db.get(SimFinding, target.id).status == "OPEN"                    # still present -> still open
    lifecycle.execute(env, "s3.make_private", target.resource_id, {})
    scan, _ = run_scan(db, row, env, trigger="manual", actor="t")
    db.commit()
    resolved = db.get(SimFinding, target.id)
    assert resolved.status == "RESOLVED" and resolved.resolved_scan_id == scan.id and resolved.resolved_at is not None


def test_cost_engine_reads_persisted_history(stored):
    db, row, env = stored
    loaded = env_store.load(db, row)
    from app.engines import cost
    assert cost.history(loaded, 30) == cost.history(env, 30)
    assert cost.monthly_run_rate(loaded)["total"] == cost.monthly_run_rate(env)["total"]


def test_analysis_over_loaded_environment_equals_analysis_over_original(stored):
    db, row, env = stored
    a, b = analysis.analyze(env_store.load(db, row)), analysis.analyze(env)
    assert [f["finding_key"] for f in a["findings"]] == [f["finding_key"] for f in b["findings"]]
    assert a["monthly_run_rate"] == b["monthly_run_rate"] and a["security_score"] == b["security_score"]


def test_only_one_environment_is_active_and_archived_ones_keep_their_rows(db):
    first = env_store.create_environment(db, generate_environment(SimConfig(seed=1)))
    db.commit()
    second = env_store.create_environment(db, generate_environment(SimConfig(seed=2)))
    db.commit()
    assert env_store.active_row(db).id == second.id
    assert db.get(type(first), first.id).status == "ARCHIVED" and db.get(type(first), first.id).archived_at is not None
    assert db.scalar(select(func.count()).select_from(SimResource).where(SimResource.environment_id == first.id)) > 0


def test_state_version_counts_mutations_and_scans_record_the_version_they_saw(sim):
    c, h = sim
    from app.database import SessionLocal
    with SessionLocal() as db:
        v0 = env_store.active_row(db).state_version
        scan_v = db.scalar(select(SimScan.state_version).order_by(SimScan.id.desc()))
    assert scan_v == v0
    c.post("/api/sim/resources/actions", headers=h, json={"action": "eip.allocate"})
    c.post("/api/sim/time/advance", headers=h, json={"days": 1})
    with SessionLocal() as db:
        assert env_store.active_row(db).state_version == v0 + 2
