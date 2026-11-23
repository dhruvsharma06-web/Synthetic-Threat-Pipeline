.PHONY: dataset train test lint
# PRD acceptance: `make dataset` rebuilds the dataset from raw logs and writes a data card.
dataset:
	python -m pipeline.dataset

# `make train` compares baselines + models on the feature table and writes model.joblib + a model card.
train:
	python -m pipeline.train

test:
	python -m pytest bots pipeline -q

# same lint CI runs
lint:
	python -m ruff check bots pipeline
