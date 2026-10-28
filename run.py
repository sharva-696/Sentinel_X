import sys
from pathlib import Path

# Ensure project root and vendor directory are in python path
current_dir = Path(__file__).resolve().parent
project_root = current_dir if current_dir.name != "backend" else current_dir.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

vendor_dir = project_root / "backend" / "vendor"
if vendor_dir.is_dir() and str(vendor_dir) not in sys.path:
    sys.path.insert(0, str(vendor_dir))

if __name__ == "__main__":
    import uvicorn
    print(f"Starting Sentinel-X from {project_root}...")
    print("Dashboard available at: http://127.0.0.1:8000/dashboard/")
    print("REST API Docs at:       http://127.0.0.1:8000/docs")
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
