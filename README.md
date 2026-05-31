# Cybersecurity Threat Analysis

This repository contains the final project for the course *Visualisation & Data Science Storytelling*. The project investigates patterns in global cybersecurity incidents between 2015 and 2024 and transforms the dataset into an interactive visualisation product and accompanying documentation.

The analysis is based on the Kaggle dataset *Global Cybersecurity Threats (2015–2024)*. The dataset contains 3,000 recorded incidents from ten countries and seven target industries. It includes variables such as year, country, target industry, attack type, attack source, exploited vulnerability, defence mechanism, financial loss, number of affected users and incident resolution time.

The goal of the project is to support analysts, IT security managers and decision-makers in exploring and communicating cyber threat patterns more effectively. The visualisation focuses on descriptive and comparative insights rather than causal claims or forecasting.

## Live

* **Interactive dashboard:** https://ds24t-2-vdss-cybersecurity-datastory.streamlit.app/
* **Project documentation:** https://vdss-fs26-ds24t.github.io/ds24t-2-vdss-project/

The documentation website contains the project charta, data report, visualisation design report, evaluation, meeting notes and presentation.

## Quick Start

Install the project environment:

```bash
uv sync
```

Load or prepare the data:

```bash
uv run data_acquisition/load.py
```

Generate the static HTML dashboard:

```bash
cd eda
uv run python generate-data-profile.py ../data/raw/Global_Cybersecurity_Threats_2015-2024.csv
cd ..
```

Run the deployed Streamlit application locally:

```bash
uv run streamlit run deployment/app.py
```

Preview the Quarto documentation website locally:

```bash
cd docs
quarto preview
```

Render the Quarto documentation website:

```bash
cd docs
uv run quarto render
```

## Project Organisation

The project is organised according to the main phases of the visualisation product development process.

![The visualization product development process](docs/pics/vizproductprocess.png)

| Phase                             | Relevant folders / files                                      | Documentation                                  |
| :-------------------------------- | :------------------------------------------------------------ | :--------------------------------------------- |
| Project understanding             | `docs/project_charta.qmd`                                     | Project Charta                                 |
| Data acquisition and exploration  | `data_acquisition/`, `data/`, `eda/`, `docs/data_report.qmd`  | Data Report                                    |
| Visualisation design              | `eda/generate-data-profile.py`, `docs/viz_design_report.qmd`  | Visualisation Design Report                    |
| Evaluation                        | `docs/evaluation.qmd`                                         | Evaluation                                     |
| Deployment                        | `deployment/app.py`, `.github/workflows/`, `docs/_quarto.yml` | Documentation website and dashboard deployment |
| Meetings and project coordination | `docs/meeting_notes.qmd`, `README.md`                         | Meeting Notes and repository overview          |

## Important Files

| File / folder                  | Purpose                                                                                                                                     |
| :----------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `eda/generate-data-profile.py` | Generates the static interactive HTML dashboard from the cybersecurity dataset. Design changes to the static dashboard should be made here. |
| `eda/dashboard.html`           | Generated static dashboard output. This file should not be edited manually.                                                                 |
| `deployment/app.py`            | Streamlit deployment of the interactive dashboard.                                                                                          |
| `docs/`                        | Quarto documentation website.                                                                                                               |
| `docs/_quarto.yml`             | Quarto website configuration and sidebar navigation.                                                                                        |
| `docs/data_report.qmd`         | Dataset description, data quality checks and exploratory analysis.                                                                          |
| `docs/viz_design_report.qmd`   | Design rationale and explanation of the visualisation product.                                                                              |
| `docs/evaluation.qmd`          | Evaluation of the dashboard against the project goals and user needs.                                                                       |
| `docs/meeting_notes.qmd`       | Relevant coaching and internal team meeting notes.                                                                                          |
