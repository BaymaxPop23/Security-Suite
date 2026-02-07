"""Agent communication and messaging system"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid
import json
from pathlib import Path
from collections import defaultdict


class AgentMessage(BaseModel):
    """Message sent between agents"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_agent: str  # Agent name (e.g., "Scout", "Hunter")
    to_agent: str    # Agent name or "broadcast" for all
    message_type: str  # "question", "insight", "request", "response", "announcement"
    content: Dict[str, Any]
    thread_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    priority: str = "normal"  # "low", "normal", "high", "urgent"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "from": self.from_agent,
            "to": self.to_agent,
            "type": self.message_type,
            "content": self.content,
            "thread_id": self.thread_id,
            "timestamp": self.timestamp.isoformat(),
            "priority": self.priority
        }


class ConversationThread(BaseModel):
    """A conversation thread between agents"""
    thread_id: str
    participants: List[str]
    messages: List[AgentMessage] = Field(default_factory=list)
    topic: Optional[str] = None
    started_at: datetime = Field(default_factory=datetime.now)
    status: str = "active"  # "active", "resolved", "archived"


class MessageBus:
    """
    Central message bus for agent communication

    Features:
    - Direct messaging between agents
    - Broadcast messages to all agents
    - Conversation threading
    - Message history and search
    - Priority-based routing
    """

    def __init__(self, storage_dir: str = "messages"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # In-memory message queues per agent
        self.queues: Dict[str, List[AgentMessage]] = defaultdict(list)

        # Conversation threads
        self.threads: Dict[str, ConversationThread] = {}

        # Broadcast subscribers
        self.broadcast_subscribers: List[str] = []

    def send_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: str,
        content: Dict[str, Any],
        thread_id: Optional[str] = None,
        priority: str = "normal"
    ) -> AgentMessage:
        """
        Send a message from one agent to another

        Args:
            from_agent: Sender agent name
            to_agent: Recipient agent name or "broadcast"
            message_type: Type of message
            content: Message content
            thread_id: Optional conversation thread ID
            priority: Message priority

        Returns:
            AgentMessage object
        """
        message = AgentMessage(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            thread_id=thread_id,
            priority=priority
        )

        # Add to recipient's queue
        if to_agent == "broadcast":
            for agent in self.broadcast_subscribers:
                if agent != from_agent:  # Don't send to self
                    self.queues[agent].append(message)
        else:
            self.queues[to_agent].append(message)

        # Add to thread if specified
        if thread_id and thread_id in self.threads:
            self.threads[thread_id].messages.append(message)

        # Persist message
        self._persist_message(message)

        return message

    def broadcast(
        self,
        from_agent: str,
        message_type: str,
        content: Dict[str, Any],
        priority: str = "normal"
    ) -> AgentMessage:
        """
        Broadcast a message to all agents

        Args:
            from_agent: Sender agent name
            message_type: Type of message
            content: Message content
            priority: Message priority

        Returns:
            AgentMessage object
        """
        return self.send_message(
            from_agent=from_agent,
            to_agent="broadcast",
            message_type=message_type,
            content=content,
            priority=priority
        )

    def get_messages(
        self,
        agent_name: str,
        unread_only: bool = True,
        limit: Optional[int] = None
    ) -> List[AgentMessage]:
        """
        Get messages for an agent

        Args:
            agent_name: Agent name
            unread_only: Return only unread messages
            limit: Maximum number of messages

        Returns:
            List of messages
        """
        messages = self.queues[agent_name]

        if limit:
            messages = messages[:limit]

        # Mark as read by removing from queue
        if unread_only:
            self.queues[agent_name] = []

        return messages

    def ask_agent(
        self,
        from_agent: str,
        to_agent: str,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        thread_id: Optional[str] = None
    ) -> str:
        """
        Ask another agent a question

        Args:
            from_agent: Asking agent name
            to_agent: Answering agent name
            question: Question text
            context: Additional context
            thread_id: Optional thread ID

        Returns:
            Thread ID for tracking the conversation
        """
        if thread_id is None:
            thread_id = self.create_thread(
                participants=[from_agent, to_agent],
                topic=f"Question from {from_agent}"
            )

        self.send_message(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type="question",
            content={
                "question": question,
                "context": context or {}
            },
            thread_id=thread_id,
            priority="high"
        )

        return thread_id

    def respond_to_message(
        self,
        from_agent: str,
        original_message: AgentMessage,
        response_content: Dict[str, Any]
    ) -> AgentMessage:
        """
        Respond to a message

        Args:
            from_agent: Responding agent name
            original_message: Message being responded to
            response_content: Response content

        Returns:
            Response message
        """
        return self.send_message(
            from_agent=from_agent,
            to_agent=original_message.from_agent,
            message_type="response",
            content={
                "in_response_to": original_message.id,
                **response_content
            },
            thread_id=original_message.thread_id
        )

    def create_thread(
        self,
        participants: List[str],
        topic: Optional[str] = None
    ) -> str:
        """
        Create a new conversation thread

        Args:
            participants: List of agent names
            topic: Thread topic

        Returns:
            Thread ID
        """
        thread_id = str(uuid.uuid4())
        thread = ConversationThread(
            thread_id=thread_id,
            participants=participants,
            topic=topic
        )
        self.threads[thread_id] = thread
        return thread_id

    def get_thread(self, thread_id: str) -> Optional[ConversationThread]:
        """Get a conversation thread by ID"""
        return self.threads.get(thread_id)

    def get_thread_messages(self, thread_id: str) -> List[AgentMessage]:
        """Get all messages in a thread"""
        thread = self.get_thread(thread_id)
        return thread.messages if thread else []

    def subscribe_to_broadcasts(self, agent_name: str):
        """Subscribe an agent to broadcast messages"""
        if agent_name not in self.broadcast_subscribers:
            self.broadcast_subscribers.append(agent_name)

    def get_conversation_history(
        self,
        agent_name: str,
        with_agent: Optional[str] = None,
        limit: int = 50
    ) -> List[AgentMessage]:
        """
        Get conversation history for an agent

        Args:
            agent_name: Agent name
            with_agent: Optional other agent to filter by
            limit: Maximum messages

        Returns:
            List of messages
        """
        history_file = self.storage_dir / f"{agent_name}_history.jsonl"

        if not history_file.exists():
            return []

        messages = []
        with open(history_file, 'r') as f:
            for line in f:
                try:
                    msg_data = json.loads(line)
                    if with_agent:
                        if msg_data['from'] == with_agent or msg_data['to'] == with_agent:
                            messages.append(AgentMessage(**msg_data))
                    else:
                        messages.append(AgentMessage(**msg_data))
                except:
                    continue

        return messages[-limit:]

    def _persist_message(self, message: AgentMessage):
        """Persist message to storage"""
        # Save to sender's history
        sender_file = self.storage_dir / f"{message.from_agent}_history.jsonl"
        with open(sender_file, 'a') as f:
            f.write(json.dumps(message.to_dict()) + '\n')

        # Save to recipient's history
        if message.to_agent != "broadcast":
            recipient_file = self.storage_dir / f"{message.to_agent}_history.jsonl"
            with open(recipient_file, 'a') as f:
                f.write(json.dumps(message.to_dict()) + '\n')

    def get_stats(self) -> Dict[str, Any]:
        """Get message bus statistics"""
        return {
            "total_threads": len(self.threads),
            "active_threads": len([t for t in self.threads.values() if t.status == "active"]),
            "broadcast_subscribers": len(self.broadcast_subscribers),
            "queued_messages": {agent: len(msgs) for agent, msgs in self.queues.items()},
        }


# Global message bus instance
_message_bus = None

def get_message_bus() -> MessageBus:
    """Get or create global message bus"""
    global _message_bus
    if _message_bus is None:
        _message_bus = MessageBus()
    return _message_bus
