.PHONY: dataset test
# PRD acceptance: `make dataset` rebuilds the dataset from raw logs and writes a data card.
dataset:
	python -m pipeline.dataset

test:
	python -m pytest bots pipeline -q
