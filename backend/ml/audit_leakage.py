import pandas as pd
import numpy as np
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
import tldextract

from ml.train import load_dataset, clean_dataset, _domain_aware_split

def audit_leakage():
    # Load and prep dataset again exactly as in train.py
    _PROJECT_ROOT = Path(__file__).resolve().parent.parent
    ds_path = _PROJECT_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if not ds_path.exists():
        print(f"Dataset not found at {ds_path}")
        return

    df = load_dataset(ds_path, invert_labels=True)
    df = clean_dataset(df)

    # Perform the split as in train.py
    train, val, test = _domain_aware_split(df)

    def get_domains(df):
        from urllib.parse import urlparse
        def _registered_domain(url: str) -> str:
            try:
                host = urlparse(url).hostname or ""
                ext = tldextract.extract(host)
                reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                return reg.lower()
            except Exception:
                return url
        return set(df["url"].apply(_registered_domain))

    train_domains = get_domains(train)
    val_domains = get_domains(val)
    test_domains = get_domains(test)

    print(f"Unique domains:")
    print(f"Train: {len(train_domains)}")
    print(f"Val:   {len(val_domains)}")
    print(f"Test:  {len(test_domains)}")

    print(f"\nIntersection counts:")
    print(f"Train/Val:  {len(train_domains.intersection(val_domains))}")
    print(f"Train/Test: {len(train_domains.intersection(test_domains))}")
    print(f"Val/Test:   {len(val_domains.intersection(test_domains))}")
    print(f"Train/Val/Test: {len(train_domains.intersection(val_domains).intersection(test_domains))}")

if __name__ == "__main__":
    audit_leakage()
