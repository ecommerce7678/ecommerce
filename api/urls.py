from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ProductViewSet,
    CategoryViewSet,
    CartItemViewSet,
    OrderViewSet,
    WishlistItemViewSet,
    CouponViewSet,
    AddressViewSet,
    # Agar ReturnRequestViewSet banaya hai to yeh bhi add kar sakte ho
    ReturnRequestViewSet,
    UserViewSet,
    VerifyOTPAndAuthView,
    SendOTPView,
    CurrentUserView,
    RegisterView,
)

router = DefaultRouter()

# Yeh sab viewset mein queryset class attribute nahi hai → basename dena zaroori hai
router.register(r'products', ProductViewSet, basename='product')                 # isme queryset hai → basename optional
router.register(r'categories',  CategoryViewSet)               # isme bhi queryset hai → optional
router.register(r'cart',        CartItemViewSet,    basename='cart')
router.register(r'orders',      OrderViewSet,       basename='order')
router.register(r'wishlist',    WishlistItemViewSet,basename='wishlist')
router.register(r'coupons',     CouponViewSet)                 # ReadOnlyModelViewSet → basename optional
router.register(r'addresses',   AddressViewSet,     basename='address')
router.register(r'users',       UserViewSet)

# Agar ReturnRequest ke liye alag ViewSet banaya hai (recommended)
router.register(r'return-requests', ReturnRequestViewSet, basename='return-request')

# Optional: custom non-router endpoints (agar future mein chahiye)
# from .views import some_custom_view
# urlpatterns_custom = [
#     path('custom-action/', some_custom_view, name='custom-action'),
# ]

urlpatterns = [
    path('users/me/', CurrentUserView.as_view(), name='current-user'),
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('auth/send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('auth/verify-otp/', VerifyOTPAndAuthView.as_view(), name='verify-otp'),
]