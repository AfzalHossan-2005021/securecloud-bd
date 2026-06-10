# paper/

IEEE-format LaTeX paper: *SecureCloud-BD: ML-Driven Anomaly Detection for
Kubernetes-Native Cloud Workloads*.

## Build

Requires a LaTeX distribution with `pdflatex` and `bibtex` (e.g., TeX Live 2023+).

```bash
cd paper
make          # runs pdflatex → bibtex → pdflatex × 2
make clean    # remove build artefacts
```

Or manually:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

## File layout

```
paper/
├── main.tex              Top-level document (IEEEtran class)
├── references.bib        BibTeX bibliography
├── Makefile
├── sections/
│   ├── 01_introduction.tex
│   ├── 02_related_work.tex
│   ├── 03_system_design.tex   ← feature table, architecture description
│   ├── 04_ml_pipeline.tex     ← ensemble equations
│   ├── 05_evaluation.tex      ← result tables (fill in after experiments)
│   ├── 06_discussion.tex
│   └── 07_conclusion.tex
└── figures/
    ├── architecture.pdf       ← generate from draw.io / Inkscape
    └── roc_curves.pdf         ← generate with ml/training/train.py --plot
```

## TODO before submission

- [ ] Run experiments on UNSW-NB15 and CIC-IDS2017; fill in Tables II and III in `05_evaluation.tex`
- [ ] Run attack simulations; fill in Table IV (detection latency)
- [ ] Export `figures/architecture.pdf`
- [ ] Export `figures/roc_curves.pdf`
- [ ] Replace `[University Name]` placeholder in `main.tex`
- [ ] Replace GitHub URL placeholder in `07_conclusion.tex`
- [ ] Spell-check and grammar-check full draft
