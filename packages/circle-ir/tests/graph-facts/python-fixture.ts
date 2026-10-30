/** A small Python service for the Python graph-facts tests. */

export const PY_APP: Record<string, string> = {
  'src/shop/__init__.py': 'from .service import OrderService\n',
  'src/shop/app.py': `from flask import Flask, Blueprint
from .api import api

app = Flask(__name__)
app.register_blueprint(api, url_prefix="/v1")

@app.route("/health")
def health():
    return "ok"
`,
  'src/shop/api.py': `from flask import Blueprint
from shop import OrderService
from . import util

api = Blueprint("api", __name__, url_prefix="/orders")
service = OrderService()

@api.route("/<int:oid>", methods=["GET", "DELETE"])
def order(oid: int):
    return service.get(oid)

@api.post("/")
def create():
    return util.slug(service.create())
`,
  'src/shop/service.py': `from .store import Store, MemStore

class OrderService:
    def __init__(self, store: Store = None):
        self.store = store or MemStore()
        self.cache: MemStore = MemStore()

    def get(self, oid):
        return self.cache.load(oid)

    def create(self):
        return self._new()

    def _new(self):
        return sorted([1, 2], key=self._key)

    def _key(self, x):
        return x

    def unused(self):
        return 1

    def only_tested(self):
        return 2

    def __repr__(self):
        return "OrderService"

    @property
    def size(self):
        return 0
`,
  'src/shop/store.py': `class Store:
    def load(self, oid):
        raise NotImplementedError

class MemStore(Store):
    def load(self, oid):
        return oid

    def legacy(self):
        pass
`,
  'src/shop/util.py': `def slug(x):
    return str(x).lower()

def dead_helper():
    return slug("x")
`,
  'src/shop/cli.py': `import click

@click.group()
def cli():
    pass

@cli.command()
def sync():
    pass

def main():
    cli()

if __name__ == "__main__":
    main()
`,
  'src/shop/tasks.py': `from celery import shared_task

@shared_task
def nightly():
    pass
`,
  'src/shop/urls.py': `from django.urls import path
from . import views

urlpatterns = [
    path("items/<int:pk>/", views.item),
    path("about/", views.About.as_view()),
]
`,
  'src/shop/views.py': `def item(request, pk):
    return pk

class About:
    def get(self, request):
        return "about"
`,
  'tests/test_service.py': `import pytest
from shop.service import OrderService

@pytest.fixture
def svc():
    return OrderService()

def test_only(svc):
    assert svc.only_tested() == 2

class TestOrders:
    def test_get(self, svc):
        svc.get(1)
`,
};

export const PYPROJECT = `[project]
name = "shop"

[project.scripts]
shop = "shop.cli:main"
missing = "shop.gone:run"
`;
