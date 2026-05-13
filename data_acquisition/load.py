
# Dataset: https://www.kaggle.com/datasets/atharvasoundankar/global-cybersecurity-threats-2015-2024
# Change .env for kaggle username and api key


from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

KAGGLE_DATASET = "atharvasoundankar/global-cybersecurity-threats-2015-2024"
RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"
CSV_NAME = "Global_Cybersecurity_Threats_2015-2024.csv"


def download(force: bool = False) -> Path:

    import kaggle

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RAW_DIR / CSV_NAME

    if csv_path.exists() and not force:
        return csv_path

    kaggle.api.authenticate()
    kaggle.api.dataset_download_files(
        KAGGLE_DATASET,
        path=str(RAW_DIR),
        unzip=True,
        quiet=False,
    )
    return csv_path


# Convert to df
def load(download_if_missing: bool = True) -> pd.DataFrame:

    csv_path = RAW_DIR / CSV_NAME

    if not csv_path.exists():
        if not download_if_missing:
            raise FileNotFoundError(
                f"Dataset not found at {csv_path}. "
                "Run load.download() or set download_if_missing=True."
            )
        csv_path = download()

    df = pd.read_csv(csv_path)

    df.columns = (
        df.columns
        .str.strip()
        .str.lower()
        .str.replace(r"[\s/]+", "_", regex=True)
        .str.replace(r"[^\w]", "", regex=True)
    )

    return df


if __name__ == "__main__":
    df = load()
    print(f"Loaded {len(df):,} rows × {df.shape[1]} columns")
    print(df.dtypes)
    print(df.head())
