"""Session-scoped bounded SSE broker, adapted from Redforge's EventBroker."""
import asyncio


class EventBroker:
    def __init__(self):
        self.subscribers = {}

    def subscribe(self, scope):
        queue = asyncio.Queue(maxsize=128)
        self.subscribers.setdefault(scope, set()).add(queue)
        return queue

    def unsubscribe(self, scope, queue):
        queues = self.subscribers.get(scope, set())
        queues.discard(queue)
        if not queues:
            self.subscribers.pop(scope, None)

    async def publish(self, scope, event):
        for queue in list(self.subscribers.get(scope, set())):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)
