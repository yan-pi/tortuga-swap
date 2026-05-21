PAPER  := paper
LATEXMK := latexmk -pdf -interaction=nonstopmode -halt-on-error

# Requirements (full TeXLive needed for acmart):
#   macOS  : brew install --cask mactex-no-gui
#   NixOS  : nix-shell -p texliveFull
#   Ubuntu : apt install texlive-full   (or at minimum: texlive-publishers,
#              texlive-bibtex-extra, biber, latexmk)
# Sanity check : kpsewhich acmart.cls    (must print a path)

.PHONY: all clean watch figures tables check-deps

check-deps:
	@kpsewhich acmart.cls >/dev/null 2>&1 \
	  || { echo "acmart.cls not found -- install texlive-publishers / texliveFull"; exit 1; }
	@command -v latexmk >/dev/null 2>&1 || { echo "latexmk missing"; exit 1; }

all: check-deps $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex references.bib
	$(LATEXMK) $(PAPER).tex

watch:
	$(LATEXMK) -pvc $(PAPER).tex

# Regenerate tables and figures from raw CSV data (deliverable #4 wires these)
figures:
	python3 analysis/run.py --emit-figures
tables:
	python3 analysis/run.py --emit-tables

clean:
	latexmk -C
	rm -f *.aux *.log *.out *.bbl *.blg *.fdb_latexmk *.fls *.synctex.gz
