from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from decimal import Decimal

from .models import (
    CustomUser,
    Address,
    Category,
    Product,
    CartItem,
    Order,
    OrderItem,
    Coupon,
    WishlistItem,
    ReturnRequest,
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'phone', 'first_name', 'last_name']
        read_only_fields = ['id']


class CurrentUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'phone']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        label="Confirm password",
        style={'input_type': 'password'}
    )

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password2', 'phone')
        extra_kwargs = {
            'email': {'required': True},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Both password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            phone=validated_data.get('phone'),
            password=validated_data['password'],
        )
        return user


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'
        read_only_fields = ['user', 'created_at']


class CategorySerializer(serializers.ModelSerializer):
    product_count = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'parent', 'is_active', 'created_at', 'product_count', 'image']

    def get_product_count(self, obj):
        return obj.products.count()


class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.all(),
        source='category',
        write_only=True,
        required=False
    )

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'slug', 'category', 'category_id', 'return_window_days',
            'description', 'price', 'discount_price', 'stock', 'shipping_charge',
            'image', 'is_available', 'created_at', 'updated_at'
        ]
        read_only_fields = ['slug', 'created_at', 'updated_at']


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        source='product',
        write_only=True
    )
    item_shipping = serializers.SerializerMethodField()

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'product_id', 'quantity', 'created_at', 'updated_at', 'item_shipping']
        read_only_fields = ['created_at', 'updated_at']

    def get_item_shipping(self, obj):
        return float(obj.product.shipping_charge * obj.quantity)


class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'quantity', 'price', 'subtotal']
        read_only_fields = ['subtotal']


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    address = AddressSerializer(read_only=True)
    user = UserSerializer(read_only=True)

    # Return window calculation fields
    min_return_window_days = serializers.SerializerMethodField()
    can_be_returned = serializers.SerializerMethodField()
    days_left_for_return = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            'id',
            'order_number',
            'user',
            'address',
            'subtotal',
            'discount',
            'tax',
            'shipping',
            'total_amount',
            'final_amount',
            'status',
            'payment_method',
            'payment_status',
            'return_status',
            'min_return_window_days',
            'can_be_returned',
            'days_left_for_return',
            'created_at',
            'updated_at',
            'delivered_at',
            'items',
        ]
        read_only_fields = [
            'order_number',
            'user',
            'subtotal',
            'discount',
            'tax',
            'shipping',
            'total_amount',
            'final_amount',
            'created_at',
            'updated_at',
            'delivered_at',
            'return_status',
            'min_return_window_days',
            'can_be_returned',
            'days_left_for_return',
        ]

    def get_min_return_window_days(self, obj):
        if not obj.items.exists():
            return 0

        windows = [
            item.product.return_window_days
            for item in obj.items.select_related('product')
        ]

        return min(windows) if windows else 0

    def get_can_be_returned(self, obj):
        if obj.status != 'DELIVERED':
            return False

        if not obj.delivered_at:
            return False

        min_days = self.get_min_return_window_days(obj)

        if min_days <= 0:
            return False

        deadline = obj.delivered_at + timezone.timedelta(days=min_days)
        return timezone.now() <= deadline

    def get_days_left_for_return(self, obj):
        if not self.get_can_be_returned(obj):
            return 0

        min_days = self.get_min_return_window_days(obj)
        deadline = obj.delivered_at + timezone.timedelta(days=min_days)
        delta = deadline - timezone.now()

        return max(0, delta.days)


class CouponSerializer(serializers.ModelSerializer):
    class Meta:
        model = Coupon
        fields = [
            'id', 'code', 'discount_percent', 'discount_amount', 'discount_type',
            'min_amount', 'max_uses', 'uses_count', 'valid_from', 'valid_to',
            'active', 'created_at'
        ]
        read_only_fields = ['uses_count', 'created_at']


class WishlistItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        source='product',
        write_only=True
    )

    class Meta:
        model = WishlistItem
        fields = ['id', 'product', 'product_id', 'added_at']
        read_only_fields = ['added_at']


class ReturnRequestSerializer(serializers.ModelSerializer):
    order_number = serializers.CharField(source='order.order_number', read_only=True)
    product_name = serializers.CharField(
        source='order_item.product.name',
        read_only=True,
        allow_null=True
    )
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = ReturnRequest
        fields = [
            'id',
            'order',
            'order_number',
            'order_item',
            'product_name',
            'quantity',
            'reason',
            'description',
            'images',
            'status',
            'admin_remarks',
            'refund_amount',
            'requested_at',
            'updated_at',
            'username',
        ]
        read_only_fields = [
            'id',
            'user',
            'requested_at',
            'updated_at',
            'refund_amount',
            'username',
            'order_number',
            'product_name',
        ]