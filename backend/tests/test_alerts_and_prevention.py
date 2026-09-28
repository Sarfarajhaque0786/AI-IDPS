def test_generate_high_severity_and_check_alert(test_client, auth_headers):
    test_client.post("/api/simulation/generate", json={"scenario": "HIGH_CONNECTION_RATE", "count": 5}, headers=auth_headers)
    res = test_client.post("/api/detection/analyze", headers=auth_headers)
    assert res.status_code == 200

    alerts_res = test_client.get("/api/alerts", headers=auth_headers)
    assert alerts_res.status_code == 200
    assert isinstance(alerts_res.json(), list)


def test_update_alert_status(test_client, auth_headers):
    alerts_res = test_client.get("/api/alerts", headers=auth_headers)
    alerts = alerts_res.json()
    if not alerts:
        return
    alert_id = alerts[0]["id"]
    res = test_client.patch(f"/api/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"}, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"


def test_prevention_blocked_list(test_client, auth_headers):
    res = test_client.get("/api/prevention/blocked", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_manual_block_and_unblock(test_client, auth_headers):
    res = test_client.post("/api/prevention/block", json={"source_ip": "203.0.113.99", "reason": "test block"}, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["source_identifier"] == "203.0.113.99"

    res2 = test_client.post("/api/prevention/unblock", json={"source_ip": "203.0.113.99"}, headers=auth_headers)
    assert res2.status_code == 200