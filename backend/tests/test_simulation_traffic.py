def test_generate_simulation_and_detect(test_client, auth_headers):
    res = test_client.post("/api/simulation/generate", json={"scenario": "BRUTE_FORCE", "count": 3}, headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["generated_count"] == 3

    res2 = test_client.post("/api/detection/analyze", headers=auth_headers)
    assert res2.status_code == 200
    assert res2.json()["analyzed"] >= 3


def test_traffic_stats(test_client, auth_headers):
    res = test_client.get("/api/traffic/stats", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert data["total_events"] >= 0


def test_traffic_list_requires_auth(test_client):
    res = test_client.get("/api/traffic")
    assert res.status_code in (401, 403)