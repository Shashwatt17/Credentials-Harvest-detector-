from fastapi import FastAPI
from pydantic import BaseModel
import psycopg2
import os
import numpy as np
import math
from sklearn.ensemble import IsolationForest
from fastapi.middleware.cors import CORSMiddleware

# ---------------- APP INITIALIZATION ----------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DATABASE CONNECTION ----------------

conn = psycopg2.connect(
    database="cred_detect",
    user="postgres",
    password=os.getenv("DB_PASSWORD"),
    host="localhost",
    port="5432"
)

cursor = conn.cursor()

# Create EVENTS table
cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp VARCHAR(100),
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    domain VARCHAR(255),
    method VARCHAR(10)
);
""")

# Create ALERTS table
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp VARCHAR(100),
    domain VARCHAR(255),
    score INTEGER,
    reason VARCHAR(255)
);
""")

conn.commit()

# ---------------- AI MODEL SETUP ----------------

model = IsolationForest(contamination=0.1)
MODEL_TRAINED = False
EVENT_COUNTER = 0
RETRAIN_THRESHOLD = 20  # retrain every 20 events

# ---------------- DATA MODEL ----------------

class Event(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    domain: str
    method: str

# ---------------- ENTROPY CALCULATION ----------------

def calculate_entropy(domain):
    probability = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    entropy = - sum([p * math.log2(p) for p in probability])
    return entropy

# ---------------- RULE-BASED SCORING ----------------

def calculate_score(event):
    score = 0
    reason = []

    if event.method.upper() == "POST":
        score += 3
        reason.append("POST request detected")

    suspicious_keywords = ["login", "secure", "verify", "update"]

    for word in suspicious_keywords:
        if word in event.domain.lower():
            score += 2
            reason.append(f"Suspicious keyword: {word}")

    entropy = calculate_entropy(event.domain)

    if entropy > 3.5:
        score += 2
        reason.append("High domain entropy detected")

    return score, ", ".join(reason)

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(domain, method):
    method_flag = 1 if method.upper() == "POST" else 0
    domain_length = len(domain)
    suspicious_word_count = sum(
        word in domain.lower()
        for word in ["login", "secure", "verify", "update"]
    )
    entropy = calculate_entropy(domain)

    return [method_flag, suspicious_word_count, domain_length, entropy]

# ---------------- ADAPTIVE MODEL TRAINING ----------------

def train_model_from_db():
    global MODEL_TRAINED

    cursor.execute("""
        SELECT domain, method
        FROM events
        ORDER BY id DESC
        LIMIT 200;
    """)

    rows = cursor.fetchall()
    feature_list = []

    for domain, method in rows:
        features = extract_features(domain, method)
        feature_list.append(features)

    if len(feature_list) > 30:
        model.fit(np.array(feature_list))
        MODEL_TRAINED = True
        print("Model trained successfully.")
    else:
        print("Not enough data to train model.")

# ---------------- STARTUP TRAINING ----------------

@app.on_event("startup")
def startup_training():
    print("Training model on startup...")
    train_model_from_db()
    print("Startup training completed.")

# ---------------- RISK CLASSIFICATION ----------------

def classify_risk(score):
    if score >= 12:
        return "CRITICAL"
    elif score >= 8:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"

# ---------------- ROOT ENDPOINT ----------------

@app.get("/")
def home():
    return {"message": "AI-Driven Credential Harvesting Detection Engine Running"}

# ---------------- MAIN EVENT INGESTION ----------------

@app.post("/api/events")
def receive_event(event: Event):

    global EVENT_COUNTER

    # Store event
    cursor.execute("""
        INSERT INTO events (timestamp, source_ip, destination_ip, domain, method)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        event.timestamp,
        event.source_ip,
        event.destination_ip,
        event.domain,
        event.method
    ))
    conn.commit()

    EVENT_COUNTER += 1

    # Periodic retraining
    if EVENT_COUNTER % RETRAIN_THRESHOLD == 0:
        train_model_from_db()

    # Rule scoring
    rule_score, reason = calculate_score(event)

    # AI scoring
    ai_score = 0

    if MODEL_TRAINED:
        features = np.array([extract_features(event.domain, event.method)])
        prediction = model.predict(features)

        if prediction[0] == -1:
            ai_score = 3

    final_score = rule_score + ai_score
    risk_level = classify_risk(final_score)

    # Alert generation
    if final_score >= 5:
        cursor.execute("""
            INSERT INTO alerts (timestamp, domain, score, reason)
            VALUES (%s, %s, %s, %s)
        """, (
            event.timestamp,
            event.domain,
            final_score,
            reason
        ))
        conn.commit()

    return {
        "rule_score": rule_score,
        "ai_score": ai_score,
        "final_score": final_score,
        "risk_level": risk_level,
        "alert_generated": final_score >= 5,
        "model_trained": MODEL_TRAINED
    }

# ---------------- ALERT FETCH ENDPOINT ----------------

@app.get("/api/alerts")
def get_alerts():
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC;")
    rows = cursor.fetchall()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "domain": row[2],
            "score": row[3],
            "reason": row[4]
        })

    return alerts