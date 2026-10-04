import os; os.environ["DATABASE_URL"] = "sqlite:///./test.db"
from fastapi.testclient import TestClient
from app import app
c = TestClient(app)
def tok(e):
    return {"Authorization": "Bearer " + c.post("/api/login", json={"email": e, "password": "Passw0rd!"}).json()["access_token"]}
def test_roles_enforced():
    assert c.get("/api/users", headers=tok("donor@lifeflow.test")).status_code == 403
    assert c.get("/api/users", headers=tok("admin@lifeflow.test")).status_code == 200
def test_request_flow_no_double_issue():
    h, s = tok("hospital@lifeflow.test"), tok("staff@lifeflow.test")
    rid = c.post("/api/requests", json={"group": "O+", "component": "red_cells", "qty": 1}, headers=h).json()["id"]
    assert c.post(f"/api/requests/{rid}/reserve", headers=s).status_code == 200
    assert c.post(f"/api/requests/{rid}/issue", headers=s).status_code == 200
    assert c.post(f"/api/requests/{rid}/issue", headers=s).status_code == 400
