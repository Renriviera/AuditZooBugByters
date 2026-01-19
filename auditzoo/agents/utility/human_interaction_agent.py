"""Human Interaction Agent with thread-based question/answer server.

This agent spawns a separate server thread on first instantiation to handle
human interaction queries. The thread runs a simple socket server that uses
input() to get answers from the user in the terminal.
"""

import asyncio
import atexit
import json
import socket
import sys
import threading
import time
from typing import ClassVar

from autogen_core import AgentId, MessageContext
from autogen_core.models import ChatCompletionClient, UserMessage

from auditzoo.core.agents.base_analysis_agent import BaseAnalysisAgent
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response
from auditzoo.core.runtime.runtime import AnalysisRuntimeError


def _human_interaction_server(port: int, stop_event: threading.Event) -> None:
    """Server thread that handles human interaction requests.

    Args:
        port: Port number to listen on
        stop_event: Event to signal server shutdown
    """

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen(20)
    server_socket.settimeout(1.0)  # Allow periodic checking of stop_event

    print(
        f"[HumanInteractionServer] Listening on port {port}",
        file=sys.stderr,
        flush=True,
    )

    def handle_client(client_socket: socket.socket) -> None:
        """Handle a single client connection in a thread.

        Args:
            client_socket: Client socket connection
        """
        try:
            # Receive question
            request = json.loads(client_socket.recv(65536).decode("utf-8"))
            question = request.get("question")
            sender = request.get("sender")
            if not question:
                response = {
                    "success": False,
                    "error": "Empty question",
                }
                client_socket.sendall(json.dumps(response).encode("utf-8"))
            else:
                if sender:
                    print(
                        "\n\n\n================================================================================\n\n\n"
                    )
                    print(
                        f"\n[Question from {sender}]: {question}",
                        file=sys.stderr,
                        flush=True,
                    )
                else:
                    print(f"\n[Question]: {question}", file=sys.stderr, flush=True)
                answer = input("\n[Your answer]: ")

                # Send response
                response = {
                    "success": True,
                    "answer": answer,
                }
                client_socket.sendall(json.dumps(response).encode("utf-8"))
        except Exception as e:
            error_response = {
                "success": False,
                "error": f"Server error: {e}",
            }
            client_socket.sendall(json.dumps(error_response).encode("utf-8"))
        finally:
            client_socket.close()

    try:
        while not stop_event.is_set():
            try:
                client_socket, _ = server_socket.accept()
                # Spawn thread for each request
                thread = threading.Thread(target=handle_client, args=(client_socket,))
                thread.daemon = True
                thread.start()
            except TimeoutError:
                continue  # Check stop_event again
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()


class HumanInteractionAgent(BaseAnalysisAgent):
    """Agent that delegates questions to a human via IPC server.

    The first instance of this agent spawns a background server process
    that handles human interaction. Subsequent instances reuse the same server.
    The server is automatically cleaned up on process exit.
    """

    _server_thread: ClassVar[threading.Thread | None] = None
    _server_port: ClassVar[int] = 0
    _stop_event: ClassVar[threading.Event | None] = None

    _lock = asyncio.Lock()

    def __init__(self, model_client: ChatCompletionClient | None = None) -> None:
        """Initialize HumanInteractionAgent.

        On first instantiation, spawns the IPC server process.

        Args:
            description: Agent description
        """
        super().__init__(description="Human interaction agent")

        self._model_client = model_client

        # Spawn server on first instance
        if HumanInteractionAgent._server_thread is None:
            self._start_server()

    def _start_server(self) -> None:
        """Start the IPC server thread if not already running."""
        if HumanInteractionAgent._server_thread is not None:
            return

        # Find available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            HumanInteractionAgent._server_port = s.getsockname()[1]

        # Create stop event
        HumanInteractionAgent._stop_event = threading.Event()

        # Start server thread
        print("Starting human interaction server thread...", file=sys.stderr)
        HumanInteractionAgent._server_thread = threading.Thread(
            target=_human_interaction_server,
            args=(
                HumanInteractionAgent._server_port,
                HumanInteractionAgent._stop_event,
            ),
            daemon=True,
        )
        HumanInteractionAgent._server_thread.start()

        # Wait for server to be ready
        time.sleep(0.2)

        max_retries = 20
        retry_delay = 0.1
        for i in range(max_retries):
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(1.0)
                test_socket.connect(("127.0.0.1", HumanInteractionAgent._server_port))
                test_socket.close()
                print(
                    f"Server ready on port {HumanInteractionAgent._server_port}",
                    file=sys.stderr,
                )
                break
            except (ConnectionRefusedError, OSError) as e:
                if i == max_retries - 1:
                    raise AnalysisRuntimeError(
                        f"Failed to start human interaction server: {e}"
                    ) from e
                time.sleep(retry_delay)

        # Register cleanup
        atexit.register(self._cleanup_server)

    @classmethod
    def _cleanup_server(cls) -> None:
        """Cleanup the server thread on exit."""
        if cls._stop_event is not None:
            cls._stop_event.set()
        if cls._server_thread is not None and cls._server_thread.is_alive():
            cls._server_thread.join(timeout=2)
            cls._server_thread = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError(f"{cls.__name__} is sealed and cannot be subclassed")

    async def _send_question(self, question: str, sender: AgentId | None) -> str:
        """Send a question to the IPC server and get response.

        Args:
            question: Question to ask the human

        Returns:
            Human's answer

        Raises:
            AnalysisRuntimeError: If communication fails
        """
        # Open async connection to server
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", HumanInteractionAgent._server_port
        )

        # Send question
        request = {
            "question": question,
            "sender": str(sender) if sender else None,
        }
        writer.write(json.dumps(request).encode("utf-8"))
        await writer.drain()

        # Receive response
        data = await reader.read(65536)
        response = json.loads(data.decode("utf-8"))

        writer.close()
        await writer.wait_closed()

        if not response.get("success", False):
            raise AnalysisRuntimeError(
                f"Server error: {response.get('error', 'Unknown error')}"
            )

        answer: str = response.get("answer", "")
        return answer

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        """Handle incoming request messages.

        Args:
            message: Request message with type "human.ask" and payload containing "question"
            ctx: Message context

        Returns:
            Response with human's answer or error
        """
        async with self._lock:
            if message.type != "human.ask":
                return Response.fail(f"Unknown task type: {message.type}")

            question = message.payload.get("question")
            if not question:
                return Response.fail("Missing 'question' in payload")

            answer = await self._send_question(question, ctx.sender)

        json_schema = message.response_schema
        if json_schema and self._model_client:
            # Use model to format answer according to schema
            prompt = (
                f'Please format the following "Answer" as a valid JSON object.\n\n'
                f"Question: {question}\n"
                f"Answer: {answer}\n\n"
                f"The JSON object must conform to the following schema:\n"
                f"{json.dumps(json_schema, indent=2)}\n\n"
            )
            response = await self._model_client.create(
                messages=[UserMessage(content=prompt, source="user")],
                json_output=True,
            )
            if isinstance(response.content, str):
                answer = json.loads(response.content)

        return Response.ok(answer)
