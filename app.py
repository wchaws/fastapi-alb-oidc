from typing import Callable, List, Tuple

import gradio as gr
import base64
import json
import requests

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.requests import HTTPConnection
from jose import jwt
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    BaseUser,
)
from starlette.middleware.authentication import AuthenticationMiddleware

app = FastAPI()


REGION = "us-west-2"


class FastAPIUser(BaseUser):
    """Sample API User that gives basic functionality"""

    def __init__(self, user_id: str, name: str, nickname: str):
        self.user_id = user_id
        self.name = name
        self.nickname = nickname

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.nickname

    @property
    def identity(self) -> str:
        return self.user_id


def decode_oidc_data(id_token: str, get_pub_key_fn: Callable[[str], str]):
    if not id_token:
        raise ValueError("Empty id token")

    jwt_headers = id_token.split(".")[0]
    decoded_jwt_headers = base64.b64decode(jwt_headers)
    decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
    decoded_json = json.loads(decoded_jwt_headers)
    kid = decoded_json["kid"]

    pub_key = get_pub_key_fn(kid)

    return jwt.decode(id_token, pub_key, algorithms=["ES256"])


def on_auth_error(request: Request, exc: Exception):
    return JSONResponse({"error": str(exc)}, status_code=401)


class FastAPIAuthBackend(AuthenticationBackend):
    """Auth Backend for FastAPI"""

    def __init__(
        self,
        excluded_urls: List[str] = [],
    ):
        """Auth Backend constructor. Part of an AuthenticationMiddleware as backend.

        Args:
            verify_header (callable): A function handle that returns a list of scopes and a BaseUser
            excluded_urls (List[str]): A list of URL paths (e.g. ['/login', '/contact']) the middleware should not check for user credentials ( == public routes)
        """
        self.excluded_urls = [] if excluded_urls is None else excluded_urls

    async def authenticate(
        self, conn: HTTPConnection
    ) -> Tuple[AuthCredentials, BaseUser]:
        """The 'magic' happens here. The authenticate method is invoked each time a route is called that the middleware is applied to.

        Args:
            conn (HTTPConnection): An HTTP connection by FastAPI/Starlette

        Returns:
            Tuple[AuthCredentials, BaseUser]: A tuple of AuthCredentials (scopes) and a user object that is or inherits from BaseUser
        """
        if conn.url.path in self.excluded_urls:
            return AuthCredentials(scopes=[]), BaseUser()

        try:
            scopes = ["hello"]

            oidc_data_jwt = conn.headers.get("x-amzn-oidc-data") or ""

            user_info = decode_oidc_data(
                oidc_data_jwt,
                get_pub_key_fn=lambda kid: requests.get(
                    f"https://public-keys.auth.elb.{REGION}.amazonaws.com/{kid}"
                ).text,
            )

        except Exception as exception:
            raise AuthenticationError(exception) from None

        return AuthCredentials(scopes=scopes), FastAPIUser(
            user_id=user_info["sub"],
            name=user_info["name"],
            nickname=user_info["nickname"],
        )


app.add_middleware(
    AuthenticationMiddleware,
    backend=FastAPIAuthBackend(excluded_urls=["/ping"]),
    on_error=on_auth_error,
)


with gr.Blocks() as demo:

    def fn(request: gr.Request):
        return request.user.name

    user = gr.Textbox(label="User: ")

    demo.load(fn, inputs=None, outputs=user)

    def echo(s: str):
        return "hello world"

    gr.Interface(echo, "textbox", "textbox")

app = gr.mount_gradio_app(app, demo, path="/")

# Then run `uvicorn --host 0.0.0.0 --port 7860 app:app --reload`
