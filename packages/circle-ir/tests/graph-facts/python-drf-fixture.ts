/** Small Django REST framework projects, one per URL-routing shape. */

/** `router.register(prefix, ViewSet)` mounted through `include(router.urls)`. */
export const PY_DRF_ROUTER: Record<string, string> = {
  'src/shop/__init__.py': '',
  'src/shop/views.py': `
from rest_framework import viewsets
from rest_framework.response import Response


class ItemViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response([])

    def retrieve(self, request, pk=None):
        return Response({})
`,
  'src/shop/urls.py': `
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r"items", views.ItemViewSet, basename="item")

urlpatterns = [
    path("api/", include(router.urls)),
]
`,
};

/** An inline `include([...])` list. */
export const PY_DRF_INLINE: Record<string, string> = {
  'src/shop/__init__.py': '',
  'src/shop/views.py': `
from django.http import HttpResponse


def ping(request):
    return HttpResponse("pong")


def items(request):
    return HttpResponse("[]")
`,
  'src/shop/urls.py': `
from django.urls import path, re_path, include
from . import views

urlpatterns = [
    path("api/", include([
        path("ping/", views.ping),
        re_path(r"^v1/", include([
            re_path(r"^items/$", views.items),
        ])),
    ])),
]
`,
};

/** A project URLconf including app URLconfs by dotted name and by imported module. */
export const PY_DRF_INCLUDE: Record<string, string> = {
  'src/project/__init__.py': '',
  'src/project/urls.py': `
from django.urls import path, include
from shop import urls as shop_urls

urlpatterns = [
    path("api/v1/", include("shop.urls")),
    path("v2/", include((shop_urls, "shop"), namespace="v2")),
    path("admin/", include("django.contrib.admin.urls")),
]
`,
  'src/shop/__init__.py': '',
  'src/shop/views.py': `
from django.http import HttpResponse


def items(request):
    return HttpResponse("[]")
`,
  'src/shop/urls.py': `
from django.urls import path
from . import views

urlpatterns = [
    path("items/", views.items),
]
`,
};

/** DRF function views with `@api_view` and generic class views. */
export const PY_DRF_VERBS: Record<string, string> = {
  'src/shop/__init__.py': '',
  'src/shop/views.py': `
from rest_framework import generics
from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["GET", "POST"])
def items(request):
    return Response([])


@api_view()
def ping(request):
    return Response("pong")


class ItemList(generics.ListCreateAPIView):
    queryset = None


class ItemDetail(generics.RetrieveDestroyAPIView):
    def destroy(self, request, *args, **kwargs):
        return Response(status=204)
`,
  'src/shop/urls.py': `
from django.urls import path
from . import views

urlpatterns = [
    path("items/", views.items),
    path("ping/", views.ping),
    path("list/", views.ItemList.as_view()),
    path("detail/<int:pk>/", views.ItemDetail.as_view()),
]
`,
};
