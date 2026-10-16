-- CloudShield PostgreSQL schema (generated from the SQLAlchemy models by scripts/generate_schema.py).
-- The API creates any missing tables at start-up, so this file is for reference and manual set-up.

CREATE TABLE IF NOT EXISTS cloud_resources (
	id SERIAL NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	resource_type VARCHAR(50) NOT NULL, 
	region VARCHAR(100) NOT NULL, 
	status VARCHAR(100) NOT NULL, 
	security_state VARCHAR(100) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_cloud_resources_id ON cloud_resources (id);
CREATE INDEX IF NOT EXISTS ix_cloud_resources_region ON cloud_resources (region);
CREATE UNIQUE INDEX IF NOT EXISTS ix_cloud_resources_resource_id ON cloud_resources (resource_id);
CREATE INDEX IF NOT EXISTS ix_cloud_resources_resource_type ON cloud_resources (resource_type);

CREATE TABLE IF NOT EXISTS cost_opportunities (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	explanation TEXT NOT NULL, 
	action TEXT NOT NULL, 
	monthly_savings NUMERIC(12, 2) NOT NULL, 
	priority VARCHAR(20) NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_cost_opportunities_id ON cost_opportunities (id);
CREATE INDEX IF NOT EXISTS ix_cost_opportunities_priority ON cost_opportunities (priority);
CREATE INDEX IF NOT EXISTS ix_cost_opportunities_resource_id ON cost_opportunities (resource_id);

CREATE TABLE IF NOT EXISTS cost_records (
	id SERIAL NOT NULL, 
	service VARCHAR(100) NOT NULL, 
	amount NUMERIC(12, 2) NOT NULL, 
	currency VARCHAR(10) NOT NULL, 
	recorded_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_cost_records_id ON cost_records (id);
CREATE INDEX IF NOT EXISTS ix_cost_records_service ON cost_records (service);

CREATE TABLE IF NOT EXISTS recommendations (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	category VARCHAR(50) NOT NULL, 
	priority VARCHAR(20) NOT NULL, 
	explanation TEXT NOT NULL, 
	action TEXT NOT NULL, 
	confidence NUMERIC(5, 2) NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_recommendations_id ON recommendations (id);
CREATE INDEX IF NOT EXISTS ix_recommendations_priority ON recommendations (priority);

CREATE TABLE IF NOT EXISTS scans (
	id SERIAL NOT NULL, 
	started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	completed_at TIMESTAMP WITHOUT TIME ZONE, 
	status VARCHAR(30) NOT NULL, 
	security_score INTEGER NOT NULL, 
	findings_count INTEGER NOT NULL, 
	monthly_cost NUMERIC(12, 2) NOT NULL, 
	potential_savings NUMERIC(12, 2) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_scans_id ON scans (id);

CREATE TABLE IF NOT EXISTS security_findings (
	id SERIAL NOT NULL, 
	title VARCHAR(255) NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	description TEXT NOT NULL, 
	risk TEXT NOT NULL, 
	recommendation TEXT NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_security_findings_id ON security_findings (id);
CREATE INDEX IF NOT EXISTS ix_security_findings_resource_id ON security_findings (resource_id);
CREATE INDEX IF NOT EXISTS ix_security_findings_severity ON security_findings (severity);

CREATE TABLE IF NOT EXISTS sim_environments (
	id SERIAL NOT NULL, 
	name VARCHAR(64) NOT NULL, 
	seed INTEGER NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	account_id VARCHAR(12) NOT NULL, 
	account_name VARCHAR(64) NOT NULL, 
	region VARCHAR(32) NOT NULL, 
	config JSONB NOT NULL, 
	sim_time TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	state_version INTEGER NOT NULL, 
	id_counters JSONB NOT NULL, 
	baseline JSONB, 
	baseline_time VARCHAR(32), 
	fingerprint VARCHAR(64), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	archived_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_environments_status ON sim_environments (status);

CREATE TABLE IF NOT EXISTS sim_saved_configs (
	id SERIAL NOT NULL, 
	name VARCHAR(64) NOT NULL, 
	config JSONB NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS users (
	id SERIAL NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(20) DEFAULT 'viewer' NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email);
CREATE INDEX IF NOT EXISTS ix_users_id ON users (id);

CREATE TABLE IF NOT EXISTS sim_audit_events (
	id SERIAL NOT NULL, 
	environment_id INTEGER, 
	timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	sim_time TIMESTAMP WITHOUT TIME ZONE, 
	actor VARCHAR(255), 
	action VARCHAR(64) NOT NULL, 
	target_type VARCHAR(32), 
	target_id VARCHAR(255), 
	outcome VARCHAR(12) NOT NULL, 
	before JSONB, 
	after JSONB, 
	details JSONB, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_audit_env_time ON sim_audit_events (environment_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_sim_audit_events_action ON sim_audit_events (action);

CREATE TABLE IF NOT EXISTS sim_cost_daily (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	service VARCHAR(40) NOT NULL, 
	cost_date DATE NOT NULL, 
	amount FLOAT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_sim_cost_env_date ON sim_cost_daily (environment_id, cost_date);

CREATE TABLE IF NOT EXISTS sim_metrics (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	metric VARCHAR(32) NOT NULL, 
	metric_date DATE NOT NULL, 
	value FLOAT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_sim_metrics_lookup ON sim_metrics (environment_id, resource_id, metric);

CREATE TABLE IF NOT EXISTS sim_recommendations (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	rec_key VARCHAR(300) NOT NULL, 
	rule_id VARCHAR(16) NOT NULL, 
	category VARCHAR(16) NOT NULL, 
	rec_type VARCHAR(48) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	resource_type VARCHAR(32) NOT NULL, 
	resource_name VARCHAR(255) NOT NULL, 
	reason TEXT NOT NULL, 
	evidence JSONB NOT NULL, 
	current_monthly_cost FLOAT NOT NULL, 
	estimated_monthly_savings FLOAT NOT NULL, 
	realized_monthly_savings FLOAT, 
	assumptions JSONB NOT NULL, 
	risk TEXT NOT NULL, 
	recommended_action TEXT NOT NULL, 
	remediation JSONB NOT NULL, 
	priority VARCHAR(8) NOT NULL, 
	confidence FLOAT NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	simulated BOOLEAN NOT NULL, 
	whatif_id INTEGER, 
	first_seen_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_seen_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	applied_at TIMESTAMP WITHOUT TIME ZONE, 
	verified_at TIMESTAMP WITHOUT TIME ZONE, 
	remediation_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_recommendations_resource_id ON sim_recommendations (resource_id);
CREATE INDEX IF NOT EXISTS ix_sim_recs_env_status ON sim_recommendations (environment_id, status);

CREATE TABLE IF NOT EXISTS sim_relationships (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	source_id VARCHAR(255) NOT NULL, 
	target_id VARCHAR(255) NOT NULL, 
	relation VARCHAR(40) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_sim_rel_env_src ON sim_relationships (environment_id, source_id);

CREATE TABLE IF NOT EXISTS sim_remediations (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	target_kind VARCHAR(16) NOT NULL, 
	target_id INTEGER NOT NULL, 
	target_key VARCHAR(300) NOT NULL, 
	plan JSONB NOT NULL, 
	plan_hash VARCHAR(16) NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	verification VARCHAR(16) NOT NULL, 
	actor VARCHAR(255), 
	executed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	executed_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	results JSONB NOT NULL, 
	before JSONB NOT NULL, 
	after JSONB NOT NULL, 
	scan_before_id INTEGER, 
	scan_after_id INTEGER, 
	cost_before FLOAT, 
	cost_after FLOAT, 
	score_before INTEGER, 
	score_after INTEGER, 
	realized_monthly_savings FLOAT, 
	message TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_remediations_environment_id ON sim_remediations (environment_id);

CREATE TABLE IF NOT EXISTS sim_reports (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	report_type VARCHAR(16) NOT NULL, 
	title VARCHAR(200) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	sim_time TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	actor VARCHAR(255), 
	content JSONB NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_reports_environment_id ON sim_reports (environment_id);

CREATE TABLE IF NOT EXISTS sim_resources (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	resource_type VARCHAR(32) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	state VARCHAR(32), 
	region VARCHAR(32), 
	data JSONB NOT NULL, 
	data_hash VARCHAR(40) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_sim_resource UNIQUE (environment_id, resource_id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_sim_resources_env_type ON sim_resources (environment_id, resource_type);

CREATE TABLE IF NOT EXISTS sim_scans (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	trigger VARCHAR(32) NOT NULL, 
	state_version INTEGER NOT NULL, 
	sim_time TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	completed_at TIMESTAMP WITHOUT TIME ZONE, 
	status VARCHAR(16) NOT NULL, 
	security_score INTEGER NOT NULL, 
	findings_open INTEGER NOT NULL, 
	new_findings INTEGER NOT NULL, 
	resolved_findings INTEGER NOT NULL, 
	severity_counts JSONB NOT NULL, 
	monthly_run_rate FLOAT NOT NULL, 
	potential_savings FLOAT NOT NULL, 
	finding_keys JSONB NOT NULL, 
	compliance JSONB NOT NULL, 
	actor VARCHAR(255), 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_scans_environment_id ON sim_scans (environment_id);

CREATE TABLE IF NOT EXISTS sim_scenario_executions (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	scenario VARCHAR(48) NOT NULL, 
	params JSONB NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	actor VARCHAR(255), 
	triggered_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	triggered_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	result JSONB NOT NULL, 
	before JSONB NOT NULL, 
	changes JSONB NOT NULL, 
	reverted_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_scenario_executions_environment_id ON sim_scenario_executions (environment_id);

CREATE TABLE IF NOT EXISTS sim_whatif_runs (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	actor VARCHAR(255), 
	title VARCHAR(200), 
	changes JSONB NOT NULL, 
	result JSONB NOT NULL, 
	baseline_fingerprint VARCHAR(64) NOT NULL, 
	state_version INTEGER NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	applied_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_whatif_runs_environment_id ON sim_whatif_runs (environment_id);

CREATE TABLE IF NOT EXISTS sim_findings (
	id SERIAL NOT NULL, 
	environment_id INTEGER NOT NULL, 
	finding_key VARCHAR(300) NOT NULL, 
	rule_id VARCHAR(16) NOT NULL, 
	rule_name VARCHAR(120) NOT NULL, 
	category VARCHAR(32) NOT NULL, 
	severity VARCHAR(12) NOT NULL, 
	severity_reason TEXT NOT NULL, 
	resource_id VARCHAR(255) NOT NULL, 
	resource_type VARCHAR(32) NOT NULL, 
	resource_name VARCHAR(255) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	explanation TEXT NOT NULL, 
	impact TEXT NOT NULL, 
	recommendation TEXT NOT NULL, 
	detection_rule TEXT NOT NULL, 
	evidence JSONB NOT NULL, 
	remediation JSONB NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	resolution VARCHAR(24), 
	first_seen_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_seen_sim TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	first_seen_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_seen_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	resolved_at TIMESTAMP WITHOUT TIME ZONE, 
	resolved_sim TIMESTAMP WITHOUT TIME ZONE, 
	first_scan_id INTEGER, 
	last_scan_id INTEGER, 
	resolved_scan_id INTEGER, 
	remediation_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(environment_id) REFERENCES sim_environments (id), 
	FOREIGN KEY(first_scan_id) REFERENCES sim_scans (id), 
	FOREIGN KEY(last_scan_id) REFERENCES sim_scans (id), 
	FOREIGN KEY(resolved_scan_id) REFERENCES sim_scans (id)
);
CREATE INDEX IF NOT EXISTS ix_sim_findings_env_status ON sim_findings (environment_id, status);
CREATE INDEX IF NOT EXISTS ix_sim_findings_key ON sim_findings (environment_id, finding_key);
CREATE INDEX IF NOT EXISTS ix_sim_findings_resource_id ON sim_findings (resource_id);
CREATE INDEX IF NOT EXISTS ix_sim_findings_rule_id ON sim_findings (rule_id);
CREATE INDEX IF NOT EXISTS ix_sim_findings_severity ON sim_findings (severity);
