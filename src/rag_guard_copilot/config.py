from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "sample_data"
LOG_DIR = ROOT_DIR / "logs"

DEFAULT_TOP_K = 5
MAX_CONTEXT_CHUNKS = 3
OPTIONAL_LLM_ENABLED = False
