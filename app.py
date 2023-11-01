from src.network.machine import Machine

me = Machine(
    ip="123456:600",
    nickname="me",
    time_token=10,
    has_token=True,
    error_probability=0.5,
    TIMEOUT_VALUE=10,
    MINIMUM_TIME=5
)

me.start()