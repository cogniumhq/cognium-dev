/** A small Python service: Flask, FastAPI, Django, click, Celery, pytest and unittest. */
export const PY_APP: Record<string, string> = {
  'src/app/__init__.py': '',
  'src/app/core.py': `
from abc import ABC
from typing import Protocol, overload


class Store(Protocol):
    def load(self, key: str) -> str: ...


class BaseStore(ABC):
    def load(self, key):
        return self.fetch(key)

    def fetch(self, key):
        raise NotImplementedError


class MemStore(BaseStore):
    def fetch(self, key):
        return key

    def __repr__(self):
        return "MemStore"

    def legacy(self):
        return 1


class UserService:
    def __init__(self, store):
        self.store = store

    def find(self, key):
        return self.store.load(key)

    def unused(self):
        return 0

    def only_tested(self):
        return 2

    def all(self, keys):
        return list(map(self.format, keys))

    def format(self, key):
        return str(key)


def make_service():
    return UserService(MemStore())


def helper():
    return 3


@overload
def coerce(x: int) -> int: ...
@overload
def coerce(x: str) -> str: ...
def coerce(x):
    return x
`,
  'src/app/web.py': `
from flask import Flask, Blueprint
from .core import make_service, helper

app = Flask(__name__)
bp = Blueprint("users", __name__, url_prefix="/users")


@app.route("/health")
def health():
    return "ok"


@bp.route("/<key>", methods=["GET", "POST"])
def get_user(key):
    return make_service().find(key)


@app.before_request
def before():
    helper()
`,
  'src/app/api.py': `
from fastapi import FastAPI, APIRouter
from app import core

api = FastAPI()
router = APIRouter(prefix="/v1")


@router.get("/items/{item_id}")
async def read_item(item_id: int):
    return core.helper()


@api.post("/echo")
def echo(body: dict):
    return body
`,
  'src/app/views.py': `
from django.views import View
from django.http import HttpResponse


def index(request):
    return HttpResponse("hi")


class ItemView(View):
    def get(self, request):
        return HttpResponse(self.render())

    def render(self):
        return "item"
`,
  'src/app/urls.py': `
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("items/", views.ItemView.as_view()),
]
`,
  'src/app/cli.py': `
import click
from app.core import make_service


@click.command()
def run():
    make_service()


if __name__ == "__main__":
    run()
`,
  'src/app/tasks.py': `
from celery import shared_task
from app.core import helper


@shared_task
def nightly():
    helper()
`,
  'src/app/management/commands/sync.py': `
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **options):
        pass
`,
  'tests/test_core.py': `
import unittest
import pytest
from app.core import UserService, MemStore


@pytest.fixture
def svc():
    return UserService(MemStore())


def test_only(svc):
    assert svc.only_tested() == 2


class CoreTest(unittest.TestCase):
    def setUp(self):
        self.s = UserService(MemStore())

    def test_find(self):
        self.s.find("a")
`,
  'src/app/dyn.py': `
import json


def go(name):
    return getattr(json, name)()
`,
};
