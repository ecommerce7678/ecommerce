import django_filters
from django.db.models import Q
from .models import Product, Category


class ProductFilter(django_filters.FilterSet):
    category = django_filters.ModelMultipleChoiceFilter(
        queryset=Category.objects.all(),
        field_name='category__slug',
        to_field_name='slug',
        method='filter_by_category_slug'
    )
    min_price = django_filters.NumberFilter(
        field_name='discount_price',
        lookup_expr='gte',
        label='Minimum price (use discount_price if available)'
    )
    max_price = django_filters.NumberFilter(
        field_name='discount_price',
        lookup_expr='lte',
        label='Maximum price'
    )
    search = django_filters.CharFilter(
        method='filter_search',
        label='Search in name or description'
    )

    class Meta:
        model = Product
        fields = []

    def filter_by_category_slug(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(category__slug__in=value)

    def filter_search(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(description__icontains=value)
        )