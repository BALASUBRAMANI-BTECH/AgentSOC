import pytest
from app.models.response import ResponseActionType
from app.response.engine import response_engine
from app.database.mongodb import db_repo


@pytest.mark.asyncio
async def test_response_execution_and_audit():
    incident_id = "INC-TEST-001"
    action = await response_engine.execute_action(
        incident_id=incident_id,
        action_type=ResponseActionType.BLOCK_IP,
        target="185.220.101.5",
        operator="SOC_ADMIN",
        simulated=True
    )

    assert action.action_id.startswith("ACT-")
    assert action.status == "EXECUTED_SIMULATED"
    assert action.target == "185.220.101.5"

    history = await response_engine.get_actions_for_incident(incident_id)
    assert len(history) >= 1
    assert history[0].action_type == ResponseActionType.BLOCK_IP

