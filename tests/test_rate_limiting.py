import asyncio
import time
import pytest
from secure_ohlcv_downloader import RateLimiter, CircuitBreaker, SecurityError

@pytest.mark.asyncio
async def test_rate_limiter_waits():
    rl = RateLimiter(1, 0.5)
    start = time.monotonic()
    await rl.acquire()
    await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.5

@pytest.mark.asyncio
async def test_circuit_breaker_opens():
    cb = CircuitBreaker(2, 0.1)

    async def fail():
        raise ValueError()

    with pytest.raises(ValueError):
        await cb.call(fail)
    with pytest.raises(ValueError):
        await cb.call(fail)
    with pytest.raises(SecurityError):
        await cb.call(fail)
    await asyncio.sleep(0.11)

    async def succeed():
        return True

    result = await cb.call(succeed)
    assert result is True
