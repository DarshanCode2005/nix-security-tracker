from django.db.models import QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework.generics import ListAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.views import APIView

from api.matching.serializers import MatchingTrainingRecordSerializer
from api.serializers import ErrorDetailSerializer
from shared.auth import isadmin
from shared.matching_training_data import user_curated_proposals
from shared.models.linkage import CVEDerivationClusterProposal


class IsAdmin(BasePermission):
    """Staff or security-team members (see shared.auth.isadmin)."""

    def has_permission(self, request: Request, view: APIView) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        return bool(request.user and isadmin(request.user))


class MatchingTrainingDataPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 100


class MatchingTrainingDataView(ListAPIView):
    """Read-only export of user-curated matching proposals for offline training."""

    permission_classes = [IsAuthenticated, IsAdmin]
    pagination_class = MatchingTrainingDataPagination
    serializer_class = MatchingTrainingRecordSerializer

    def get_queryset(self) -> QuerySet[CVEDerivationClusterProposal]:
        return user_curated_proposals()

    @extend_schema(
        operation_id="listMatchingTrainingData",
        description=(
            "Export user-curated CVE-derivation proposals "
            "(status != pending, including auto-rejects) as versioned training-data "
            "records. Requires admin privileges (staff or security team)."
        ),
        responses={
            200: MatchingTrainingRecordSerializer,
            401: ErrorDetailSerializer,
            403: ErrorDetailSerializer,
        },
    )
    def get(self, request: Request, *args: object, **kwargs: object):
        return super().get(request, *args, **kwargs)
