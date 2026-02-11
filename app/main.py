from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import analysis, uploads, symbols, ioc, annotations, investigation


app = FastAPI(
    title="VTF - Volatility Forensics Platform",
    description="Backend API for memory forensics analysis using Volatility 3",
    version="2.0.0"
)

origins = [
    "http://localhost",
    "http://localhost:5173",  # Výchozí port pro Vite
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Povolíme všechny metody (GET, POST, atd.)
    allow_headers=["*"],  # Povolíme všechny hlavičky
)

# Routery pro různé oblasti API
app.include_router(uploads.router, prefix="/api/v1", tags=["Uploads"])
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(symbols.router, prefix="/api/v1/symbols", tags=["Symbols"])
app.include_router(ioc.router, prefix="/api/v1", tags=["IOC Scanner"])
app.include_router(annotations.router, prefix="/api/v1", tags=["Annotations & Dashboard"])
app.include_router(investigation.router, prefix="/api/v1", tags=["Investigation"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the VTF API"}