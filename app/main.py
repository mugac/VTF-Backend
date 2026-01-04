from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import analysis


app = FastAPI(title="VTF - Volatility Forensics Platform")

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

app.include_router(analysis.router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"message": "Welcome to the VTF API"}