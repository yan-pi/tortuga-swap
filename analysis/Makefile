# Analysis pipeline for the tortuga-swap A2L-vs-HTLC benchmark study.
#
#   make synthetic   regenerate the synthetic benchmark CSV
#   make analyse     derive DVs, run the hypothesis tests, emit LaTeX tables
#   make             synthetic + analyse
#   make clean       remove generated data, tables and results
#
# Requires the dev shell (numpy / pandas / scipy):
#   nix develop --command make      (or run under direnv)

PYTHON  := python3
RAW     := ../data/raw/synthetic.csv
TABLES  := tables
RESULTS := results.json
SEED    := 1729

.PHONY: all synthetic analyse clean

all: synthetic analyse

# Force-regenerate the synthetic dataset.
synthetic:
	$(PYTHON) generate_synthetic.py --out $(RAW) --seed $(SEED)

# Run the statistical pipeline; regenerates the dataset only if it is missing.
analyse: $(RAW)
	$(PYTHON) run.py --input $(RAW) --tables-dir $(TABLES) \
	    --results $(RESULTS) --seed $(SEED)

$(RAW):
	$(PYTHON) generate_synthetic.py --out $(RAW) --seed $(SEED)

clean:
	rm -rf $(TABLES) $(RESULTS) $(RAW)
