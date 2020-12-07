EXTENSION = webauthn
DATA = webauthn--1.0.sql
REGRESS = test

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)