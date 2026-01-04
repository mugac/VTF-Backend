from fastapi import FastAPI
from app.api.v1.endpoints import analysis

app = FastAPI(title="VTF - Volatility Forensics Platform")

app.include_router(analysis.router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"message": "Welcome to the VTF API"}