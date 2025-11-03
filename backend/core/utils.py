from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from django.db.models import QuerySet
from rest_framework import status
from rest_framework.response import Response


def paginate_queryset(
    queryset: QuerySet[Any],
    page: int = 1,
    page_size: int = 10,
    max_page_size: int = 100,
) -> Dict[str, Any]:
    """Paginate a queryset and return paginated data."""
    if page_size > max_page_size:
        page_size = max_page_size

    start = (page - 1) * page_size
    end = start + page_size

    total = queryset.count()
    items = queryset[start:end]

    return {
        "items": items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size,
            "has_next": end < total,
            "has_prev": page > 1,
        },
    }


def create_paginated_response(
    data: List[Any],
    pagination_info: Dict[str, Any],
    message: str = "Data retrieved successfully",
) -> Response:
    """Create a standardized paginated response."""
    return Response(
        {
            "status": "success",
            "message": message,
            "data": data,
            "pagination": pagination_info,
        },
        status=status.HTTP_200_OK,
    )


def filter_by_date_range(
    queryset: QuerySet[Any],
    date_field: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> QuerySet[Any]:
    """Filter queryset by date range."""
    if start_date:
        queryset = queryset.filter(**{f"{date_field}__gte": start_date})
    if end_date:
        queryset = queryset.filter(**{f"{date_field}__lte": end_date})
    return queryset
