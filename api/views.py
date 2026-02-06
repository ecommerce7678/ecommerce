from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from decouple import config
from django.db import transaction
from django.db.models import Sum
from decimal import Decimal
from .models import (
    CustomUser, Product, Category, CartItem, Order, OrderItem, Coupon, 
    WishlistItem, Address, ReturnRequest
)
from .serializers import (
    UserSerializer, ProductSerializer, CategorySerializer, CartItemSerializer,
    OrderSerializer, CouponSerializer, WishlistItemSerializer,
    AddressSerializer, ReturnRequestSerializer, RegisterSerializer, CurrentUserSerializer
)
from .filters import ProductFilter
from .pagination import StandardResultsSetPagination
from django.core.cache import cache
from django.utils.crypto import get_random_string
from brevo_python import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail
import razorpay

# ------------------ Brevo Configuration ------------------
configuration = Configuration()
configuration.api_key['api-key'] = config("BREVO_API_KEY")

razorpay_client = razorpay.Client(auth=(
    config("RAZORPAY_KEY_ID"),
    config("RAZORPAY_KEY_SECRET")
))

api_client = ApiClient(configuration)
api_instance = TransactionalEmailsApi(api_client)

def send_otp_email(to_email: str, otp: str):
    send_smtp_email = SendSmtpEmail(
        sender={"name": "Geeta Galaxy", "email": "geetagalaxyadvertising2002@gmail.com"},
        to=[{"email": to_email}],
        subject="Your OTP Code",
        html_content=f"""
        <html>
            <body style="font-family: Arial; text-align: center;">
                <h2>Your Verification Code</h2>
                <h1 style="letter-spacing: 10px;">{otp}</h1>
                <p>This code will expire in <strong>5 minutes</strong></p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
        </html>
        """
    )
    
    try:
        api_response = api_instance.send_transac_email(send_smtp_email)
        print("Email sent! Message ID:", api_response.message_id)
        return True
    except Exception as e:
        print("Brevo Exception:", e)
        return False


class SendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        purpose = request.data.get("purpose")   # "signup" or "login"

        if not email:
            return Response({"error": "Email is required"}, status=400)

        if purpose not in ["signup", "login"]:
            return Response({"error": "Invalid purpose"}, status=400)

        # Generate 6-digit OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')

        # Store in cache for 5 minutes
        cache_key = f"otp_{purpose}_{email.lower()}"
        cache.set(cache_key, otp, timeout=300)

        success = send_otp_email(email, otp)

        if success:
            return Response({
                "message": "OTP sent successfully",
                "purpose": purpose
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Failed to send OTP"}, status=500)


class VerifyOTPAndAuthView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        purpose = request.data.get("purpose")
        username = request.data.get("username")
        phone = request.data.get("phone")

        if not all([email, otp, purpose]):
            return Response({"error": "Missing required fields"}, status=400)

        if purpose not in ["signup", "login"]:
            return Response({"error": "Invalid purpose"}, status=400)

        cache_key = f"otp_{purpose}_{email.lower()}"
        stored_otp = cache.get(cache_key)

        if not stored_otp or stored_otp != otp:
            return Response({"error": "Invalid or expired OTP"}, status=400)

        user = None

        if purpose == "signup":
            if not username:
                return Response({"error": "Username required for signup"}, status=400)

            if CustomUser.objects.filter(email__iexact=email).exists():
                return Response({"error": "Email already registered"}, status=400)

            if CustomUser.objects.filter(username__iexact=username).exists():
                return Response({"error": "Username already taken"}, status=400)

            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                phone=phone,
            )
            user.set_unusable_password()  # Important: no password login

        else:  # login
            try:
                user = CustomUser.objects.get(email__iexact=email)
            except CustomUser.DoesNotExist:
                return Response({"error": "No account found with this email"}, status=400)

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        cache.delete(cache_key)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "phone": user.phone,
            }
        }, status=status.HTTP_200_OK)

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.filter(is_active=True)
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAdminUser]
    pagination_class = StandardResultsSetPagination

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return [permissions.AllowAny()]


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-created_at')   # ← define here
    serializer_class = ProductSerializer
    filterset_class = ProductFilter
    search_fields = ['name', 'description', 'category__name']
    ordering_fields = ['price', 'discount_price', 'created_at']
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """
        Admin/staff ko sab products dikhao (available + unavailable)
        Normal user ko sirf available products dikhao
        """
        if self.request.user.is_staff:  # ya is_superuser bhi check kar sakte ho
            return Product.objects.all().order_by('-created_at')
        
        # Normal user / unauthenticated
        return Product.objects.filter(is_available=True).order_by('-created_at')

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAdminUser()]
        return [permissions.AllowAny()]

class CartItemViewSet(viewsets.ModelViewSet):
    serializer_class = CartItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """केवल लॉगिन यूज़र के cart items दिखाएँ"""
        return CartItem.objects.filter(
            user=self.request.user
        ).select_related('product')

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({'request': self.request})
        return context

    # =============================
    # ADD TO CART or INCREASE QUANTITY
    # =============================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        product_id = request.data.get('product_id')
        added_quantity = int(request.data.get('quantity', 1))

        if not product_id:
            raise ValidationError({"product_id": "This field is required."})

        try:
            product = Product.objects.get(id=product_id, is_available=True)
        except Product.DoesNotExist:
            raise ValidationError("Product not found or not available.")

        existing_item = self.get_queryset().filter(product_id=product_id).first()

        # पहले से कार्ट में है → quantity बढ़ाओ
        if existing_item:
            new_quantity = existing_item.quantity + added_quantity

            if new_quantity > product.stock:
                raise ValidationError(
                    f"Only {product.stock} items available. "
                    f"You already have {existing_item.quantity} in cart."
                )

            existing_item.quantity = new_quantity
            existing_item.save(update_fields=['quantity'])

            serializer = self.get_serializer(existing_item)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # नया आइटम
        if added_quantity > product.stock:
            raise ValidationError(f"Only {product.stock} items available.")

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # =============================
    # UPDATE QUANTITY (PUT / PATCH)
    # =============================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        """PUT - पूरा अपडेट (लेकिन हम सिर्फ quantity allow करते हैं)"""
        return self._handle_quantity_update(request, *args, **kwargs)

    @transaction.atomic
    def partial_update(self, request, *args, **kwargs):
        """PATCH - सिर्फ quantity अपडेट के लिए"""
        return self._handle_quantity_update(request, *args, **kwargs)

    def _handle_quantity_update(self, request, *args, **kwargs):
        """Common logic for both PUT and PATCH"""
        instance = self.get_object()  # automatically checks ownership via queryset

        new_quantity = request.data.get('quantity')

        if new_quantity is None:
            raise ValidationError({"quantity": "This field is required for update."})

        try:
            new_quantity = int(new_quantity)
            if new_quantity < 1:
                raise ValidationError({"quantity": "Quantity must be at least 1."})
        except (ValueError, TypeError):
            raise ValidationError({"quantity": "Quantity must be a positive integer."})

        product = instance.product

        if new_quantity > product.stock:
            raise ValidationError(
                f"Only {product.stock} items available in stock. "
                f"Current quantity: {instance.quantity}"
            )

        # अपडेट करो
        instance.quantity = new_quantity
        instance.save(update_fields=['quantity'])

        # ऑप्शनल: अगर quantity 0 हो तो डिलीट कर सकते हो (तुम्हारे ऐप के हिसाब से)
        # if new_quantity == 0:
        #     instance.delete()
        #     return Response({"detail": "Item removed from cart"}, status=status.HTTP_204_NO_CONTENT)

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # =============================
    # CART SUMMARY (with dynamic per-item shipping)
    # =============================
    @action(detail=False, methods=['get'], url_path='summary')
    def summary(self, request):
        cart_items = self.get_queryset()

        if not cart_items.exists():
            return Response({
                "subtotal": 0.0,
                "total_shipping": 0.0,
                "total": 0.0,
                "items": []
            })

        subtotal = Decimal("0.00")
        total_shipping = Decimal("0.00")

        for item in cart_items:
            price = item.product.get_display_price()  # discount price अगर लागू हो
            item_subtotal = Decimal(str(price)) * item.quantity
            subtotal += item_subtotal

            item_shipping = Decimal(str(item.product.shipping_charge)) * item.quantity
            total_shipping += item_shipping

        total = subtotal + total_shipping

        return Response({
            "subtotal": float(subtotal),
            "total_shipping": float(total_shipping),
            "total": float(total),
            "items": self.get_serializer(cart_items, many=True).data
        })

    # =============================
    # VALIDATE COUPON
    # =============================
    @action(detail=False, methods=['post'], url_path='validate_coupon')
    def validate_coupon(self, request):
        code = request.data.get("code")
        subtotal_str = request.data.get("subtotal")

        if not code:
            raise ValidationError({"code": "Coupon code is required"})

        try:
            subtotal = Decimal(str(subtotal_str))
        except Exception:
            raise ValidationError({"subtotal": "Invalid subtotal value"})

        try:
            coupon = Coupon.objects.get(code__iexact=code, active=True)
        except Coupon.DoesNotExist:
            raise ValidationError("Invalid or inactive coupon")

        now = timezone.now()

        if coupon.valid_from and now < coupon.valid_from:
            raise ValidationError("Coupon not yet active")

        if coupon.valid_to and now > coupon.valid_to:
            raise ValidationError("Coupon has expired")

        if coupon.max_uses > 0 and coupon.uses_count >= coupon.max_uses:
            raise ValidationError("Coupon usage limit reached")

        if coupon.used_by.filter(id=request.user.id).exists():
            raise ValidationError("You have already used this coupon")

        if subtotal < coupon.min_amount:
            raise ValidationError(
                f"Minimum order amount ₹{coupon.min_amount} required"
            )

        discount = coupon.calculate_discount(subtotal)

        return Response({
            "valid": True,
            "code": coupon.code,
            "discount": float(discount),
            "discount_type": coupon.discount_type,
            "final_amount_estimate": float(subtotal - discount),
            "message": f"₹{discount} discount applied!"
        }, status=status.HTTP_200_OK)


class WishlistItemViewSet(viewsets.ModelViewSet):
    serializer_class = WishlistItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WishlistItem.objects.filter(user=self.request.user).select_related('product').order_by('-added_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class AddressViewSet(viewsets.ModelViewSet):
    serializer_class = AddressSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Address.objects.filter( user=self.request.user).order_by('-created_at')


    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CouponViewSet(viewsets.ModelViewSet):
    """
    Full CRUD for Coupons + extra validation action.
    - Admin only for create/update/delete
    - Authenticated users can validate coupon
    """
    queryset = Coupon.objects.all()
    serializer_class = CouponSerializer

    def get_permissions(self):
        """
        - Create/Update/Delete → only admin
        - List/Retrieve → authenticated users
        - validate action → authenticated users
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [permissions.IsAdminUser]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        """
        Normal list mein sirf active coupons dikhao
        Admin ke liye sab dikhao
        """
        if self.request.user.is_staff:
            return Coupon.objects.all()
        return Coupon.objects.filter(active=True)

    # Custom action: Validate coupon (frontend ke liye)
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def validate(self, request):
        """Validate coupon before applying - returns discount amount"""
        code = request.data.get('code')
        subtotal_str = request.data.get('subtotal', '0')

        try:
            subtotal = Decimal(str(subtotal_str))
        except (ValueError, TypeError):
            raise ValidationError("Invalid subtotal value")

        if not code:
            raise ValidationError("Coupon code is required")

        try:
            coupon = Coupon.objects.get(code__iexact=code)
        except Coupon.DoesNotExist:
            raise ValidationError("Invalid coupon code")

        can_use, message = coupon.can_use(request.user)
        if not can_use:
            raise ValidationError(message)

        if subtotal < coupon.min_amount:
            raise ValidationError(f"Minimum order amount ₹{coupon.min_amount} required")

        discount = coupon.calculate_discount(subtotal)
        final_amount = subtotal - discount

        return Response({
            'valid': True,
            'code': coupon.code,
            'discount_type': coupon.discount_type,
            'discount_percent': coupon.discount_percent,
            'discount_amount': float(discount),
            'final_amount': float(final_amount),
            'message': f"₹{discount} discount applied!"
        }, status=status.HTTP_200_OK)

    # Optional: Create ke time extra validation (jaise valid dates check)
    def perform_create(self, serializer):
        valid_from = serializer.validated_data.get('valid_from')
        valid_to = serializer.validated_data.get('valid_to')

        if valid_from and valid_to and valid_from >= valid_to:
            raise ValidationError({"valid_to": "Valid To date must be after Valid From"})

        serializer.save()

    # Optional: Update ke time bhi date check
    def perform_update(self, serializer):
        # Same date validation as create
        self.perform_create(serializer)

class OrderViewSet(viewsets.ModelViewSet):
    pagination_class = None
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_staff:
            return Order.objects.select_related('user', 'address').prefetch_related(
                'items__product', 'return_requests'
            ).all()
        return Order.objects.filter(user=self.request.user).select_related(
            'address'
        ).prefetch_related('items__product').order_by('-created_at')

    # ... आपका पुराना create method, request_return, process_return, stats आदि सब यहीं रह सकते हैं ...

    # ────────────────────────────────────────────────────────────────
    # नया Action 1: ऑनलाइन पेमेंट के लिए Razorpay Order Create
    # ────────────────────────────────────────────────────────────────
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    @transaction.atomic
    def create_for_payment(self, request):
        """
        Flutter से ऑनलाइन पेमेंट शुरू करने के लिए:
        - Cart validate करता है
        - Coupon लागू करता है (अगर है)
        - Razorpay order create करता है
        - Django में pending order save करता है
        - Razorpay order_id और amount लौटाता है
        """
        user = request.user
        cart_items = CartItem.objects.filter(user=user)

        if not cart_items.exists():
            raise ValidationError("Your cart is empty")

        # Totals calculate
        subtotal = Decimal('0.00')
        total_shipping = Decimal('0.00')
        discount = Decimal('0.00')

        items_data = []
        for cart_item in cart_items:
            price = cart_item.product.get_display_price()  # discount price अगर लागू हो
            item_subtotal = price * cart_item.quantity
            subtotal += item_subtotal
            total_shipping += cart_item.product.shipping_charge * cart_item.quantity

            items_data.append({
                'product': cart_item.product,
                'quantity': cart_item.quantity,
                'price': price,
            })

        # Coupon लागू करो (अगर भेजा गया है)
        coupon_code = request.data.get('coupon_code')
        coupon = None
        if coupon_code:
            try:
                coupon = Coupon.objects.get(code__iexact=coupon_code, active=True)
                can_use, message = coupon.can_use(user, subtotal)
                if not can_use:
                    raise ValidationError(message)
                discount = coupon.calculate_discount(subtotal)
            except Coupon.DoesNotExist:
                raise ValidationError("Invalid or expired coupon")

        total_amount = subtotal - discount + total_shipping
        final_amount = total_amount  # अगर tax है तो यहाँ जोड़ सकते हो

        # Address validate
        address_id = request.data.get('address')
        if not address_id:
            raise ValidationError("Delivery address is required")

        try:
            address = Address.objects.get(id=address_id, user=user)
        except Address.DoesNotExist:
            raise ValidationError("Invalid or unauthorized address")

        # Razorpay order create (amount paise में)
        razorpay_order = razorpay_client.order.create({
            "amount": int(final_amount * 100),  # rupees → paise
            "currency": "INR",
            "receipt": f"receipt_{user.id}_{timezone.now().strftime('%Y%m%d%H%M%S')}",
            "payment_capture": 1  # automatic capture
        })

        # Pending order create in database
        order = Order.objects.create(
            user=user,
            address=address,
            subtotal=subtotal,
            discount=discount,
            shipping=total_shipping,
            total_amount=total_amount,
            final_amount=final_amount,
            payment_method='RAZORPAY',  # या 'ONLINE' जो आपका enum है
            payment_status='PENDING',
            status='PENDING',
            razorpay_order_id=razorpay_order['id'],
        )

        # Order items create + stock reduce
        for item in items_data:
            OrderItem.objects.create(
                order=order,
                product=item['product'],
                quantity=item['quantity'],
                price=item['price'],
                subtotal=item['price'] * item['quantity'],
            )
            # Stock कम करो
            product = item['product']
            product.stock -= item['quantity']
            product.save(update_fields=['stock'])

        # Cart clear
        cart_items.delete()

        # Coupon used mark करो
        if coupon:
            coupon.used_by.add(user)
            coupon.uses_count += 1
            coupon.save(update_fields=['uses_count'])

        # Response for Flutter (razorpay.open() के लिए जरूरी fields)
        return Response({
            "razorpay_order_id": razorpay_order['id'],
            "amount": razorpay_order['amount'],          # paise में
            "currency": "INR",
            "order_number": order.order_number,
            "order_id": order.id,                        # optional
        }, status=status.HTTP_201_CREATED)


    # ────────────────────────────────────────────────────────────────
    # नया Action 2: Payment Success पर Signature Verify
    # ────────────────────────────────────────────────────────────────
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def verify_payment(self, request):
        """
        Razorpay से payment success callback पर signature verify करने के लिए
        Signature सही होने पर order को PAID और CONFIRMED कर देता है
        """
        razorpay_order_id = request.data.get('razorpay_order_id')
        razorpay_payment_id = request.data.get('razorpay_payment_id')
        razorpay_signature = request.data.get('razorpay_signature')

        if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            raise ValidationError("Missing required payment verification fields")

        try:
            # Razorpay signature verify
            razorpay_client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            })

            # Order ढूंढो और update करो
            try:
                order = Order.objects.get(
                    razorpay_order_id=razorpay_order_id,
                    user=request.user
                )
            except Order.DoesNotExist:
                raise ValidationError("Order not found or doesn't belong to you")

            if order.payment_status == 'PAID':
                return Response({"message": "Payment already verified"}, status=200)

            order.payment_status = 'PAID'
            order.status = 'CONFIRMED'  # या 'PROCESSING' — आपके flow के अनुसार
            order.save(update_fields=['payment_status', 'status'])

            return Response({
                "status": "success",
                "message": "Payment verified successfully",
                "order_number": order.order_number
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Signature गलत या कोई और error
            raise ValidationError(f"Payment verification failed: {str(e)}")

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        print("ORDER CREATE REQUEST RECEIVED")
        print("Raw request.data:", request.data)
        print("User:", request.user)

        """Custom create method with full order processing logic"""
        user = request.user
        cart_items = CartItem.objects.filter(user=user)

        print(f"Cart items found: {cart_items.count()}")

        if not cart_items.exists():
            raise ValidationError("Your cart is empty")

        # Initialize all totals
        subtotal = Decimal('0.00')
        total_shipping = Decimal('0.00')          # ← यहाँ initialize किया → यही समस्या थी
        discount = Decimal('0.00')
        tax = Decimal('0.00')

        items_data = []

        # Process cart items
        for cart_item in cart_items:
            print(f"Processing item: product_id={cart_item.product.id}, qty={cart_item.quantity}, stock={cart_item.product.stock}")
            
            product_price = cart_item.product.get_display_price()
            item_subtotal = product_price * cart_item.quantity

            # Accumulate shipping from each item
            total_shipping += cart_item.product.shipping_charge * cart_item.quantity

            # Stock validation
            if cart_item.quantity > cart_item.product.stock:
                raise ValidationError(f"Insufficient stock for {cart_item.product.name}")

            subtotal += item_subtotal

            items_data.append({
                'product': cart_item.product,
                'quantity': cart_item.quantity,
                'price': product_price,
                'subtotal': item_subtotal
            })

        print(f"Calculated: subtotal={subtotal}, total_shipping={total_shipping}")

        # Coupon processing
        coupon_code = request.data.get('coupon_code')
        print(f"Coupon code received: '{coupon_code}'")

        coupon = None

        if coupon_code:
            try:
                coupon = Coupon.objects.get(code__iexact=coupon_code, active=True)
                print(f"Coupon found: code={coupon.code}, min_amount={coupon.min_amount}, discount_type={coupon.discount_type}")

                # पुराना can_use() चेक (expiry, used_by आदि)
                can_use, message = coupon.can_use(user, subtotal)
                print(f"Can use? {can_use} | Reason: {message}")

                if not can_use:
                    raise ValidationError(message)

                # min_amount का सही चेक → यहाँ अलग से कर रहे हैं
                if subtotal < coupon.min_amount:
                    raise ValidationError(f"Minimum ₹{coupon.min_amount} required for this coupon")

                discount = coupon.calculate_discount(subtotal)
                discount = min(discount, subtotal)  # Prevent negative order
                print(f"Discount applied: {discount}")

            except Coupon.DoesNotExist:
                print("Coupon DOES NOT EXIST in database")
                raise ValidationError("Invalid coupon code")

        # Calculate tax (18% GST example)
        tax_rate = Decimal('0.18')
        tax = (subtotal - discount) * tax_rate
        print(f"Tax calculated: {tax}")

        # Final calculations
        total_amount = subtotal - discount + tax + total_shipping
        final_amount = total_amount
        print(f"Final amount: {final_amount}")

        # Address validation
        address_id = request.data.get('address')  # Flutter से "address": id भेजा जा रहा है
        print(f"Address ID received: {address_id}")

        if not address_id:
            raise ValidationError("Address is required")

        try:
            address = Address.objects.get(id=address_id, user=user)
            print(f"Address VALID: ID={address.id}, user={address.user.username}")
        except Address.DoesNotExist:
            print(f"Address INVALID or NOT OWNED by user! ID={address_id}")
            raise ValidationError("Invalid or unauthorized address")

        # Payment method
        payment_method = request.data.get('payment_method', 'COD').upper()
        print(f"Payment method: {payment_method}")

        if payment_method not in dict(Order.PAYMENT_METHOD_CHOICES):
            raise ValidationError("Invalid payment method")

        # Create the Order
        order = Order.objects.create(
            user=user,
            address=address,
            subtotal=subtotal,
            discount=discount,
            tax=tax,
            shipping=total_shipping,
            total_amount=total_amount,
            final_amount=final_amount,
            payment_method=payment_method,
            payment_status='PENDING' if payment_method == 'COD' else 'PENDING',
            status='PENDING',
        )
        print(f"Order created: ID={order.id}, order_number={order.order_number}")

        # Create Order Items & reduce stock
        for item_data in items_data:
            OrderItem.objects.create(
                order=order,
                product=item_data['product'],
                quantity=item_data['quantity'],
                price=item_data['price'],
                subtotal=item_data['subtotal'],
            )

            # Reduce product stock
            product = item_data['product']
            product.stock -= item_data['quantity']
            product.save(update_fields=['stock'])
            print(f"Stock reduced for product {product.id}: new stock = {product.stock}")

        # Mark coupon as used
        if coupon:
            coupon.used_by.add(user)
            coupon.uses_count += 1
            coupon.save(update_fields=['uses_count'])
            print(f"Coupon used: uses_count now = {coupon.uses_count}")

        # Clear the user's cart
        cart_items.delete()
        print("Cart cleared")

        # Dummy online payment handling (replace with real gateway later)
        if payment_method != 'COD':
            # TODO: Integrate Razorpay / Stripe here
            # For now, just mark as paid (demo purpose)
            order.payment_status = 'PAID'
            order.status = 'CONFIRMED'
            order.save(update_fields=['payment_status', 'status'])
            print("Dummy online payment: marked as PAID")

        # Return the created order
        serializer = self.get_serializer(order)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def request_return(self, request, pk=None):
        """User requests return for an order"""
        order = self.get_object()
        
        if order.user != request.user:
            raise PermissionDenied("You can only return your own orders")
        
        if order.status != 'DELIVERED':
            raise ValidationError("Only delivered orders can be returned")
        
        if order.return_requested:
            raise ValidationError("Return already requested for this order")
        
        if timezone.now() > order.delivered_at + timezone.timedelta(days=7):
            raise ValidationError("Return window (7 days) has expired")

        reason = request.data.get('reason')
        if not reason:
            raise ValidationError("Return reason is required")

        # Create return request
        ReturnRequest.objects.create(
            order=order,
            user=request.user,
            reason=reason,
            description=request.data.get('description', ''),
            images=request.data.get('images', [])
        )

        order.return_requested = True
        order.return_status = 'REQUESTED'
        order.return_reason = reason
        order.return_requested_at = timezone.now()
        order.save()

        return Response({
            "detail": "Return request submitted successfully",
            "return_id": order.return_requests.last().id
        })

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAdminUser])
    def process_return(self, request, pk=None):
        """Admin processes return request"""
        order = self.get_object()
        if not order.return_requested:
            raise ValidationError("No return request found")

        action = request.data.get('action')  # 'approve', 'reject'
        if action not in ['approve', 'reject']:
            raise ValidationError("Action must be 'approve' or 'reject'")

        latest_request = order.return_requests.last()
        remarks = request.data.get('remarks', '')

        if action == 'approve':
            latest_request.status = 'APPROVED'
            order.return_status = 'APPROVED'
            order.return_approved_at = timezone.now()
            
            # Calculate refund amount (full or partial)
            if latest_request.order_item:
                refund_amount = latest_request.order_item.subtotal
            else:
                # Full order return
                refund_amount = order.final_amount
                
            latest_request.refund_amount = refund_amount
            latest_request.save()
            
            # TODO: Process actual refund (Razorpay refund API, wallet credit, etc.)
            
        else:  # reject
            latest_request.status = 'REJECTED'
            order.return_status = 'REJECTED'
            latest_request.admin_remarks = remarks

        latest_request.save()
        order.admin_remarks = remarks
        order.save()

        return Response({
            "detail": f"Return {action}d successfully",
            "return_status": order.return_status,
            "refund_amount": getattr(latest_request, 'refund_amount', 0)
        })

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Order statistics for dashboard"""
        if not request.user.is_staff:
            return Response({"detail": "Admin access required"}, status=403)
        
        thirty_days_ago = timezone.now() - timezone.timedelta(days=30)
        
        stats = {
            'total_orders': Order.objects.count(),
            'total_revenue': Order.objects.filter(
                status='DELIVERED', payment_status='PAID'
            ).aggregate(total=Sum('final_amount'))['total'] or 0,
            'pending_orders': Order.objects.filter(status='PENDING').count(),
            'delivered_orders': Order.objects.filter(status='DELIVERED').count(),
            'return_requests': Order.objects.filter(return_status='REQUESTED').count(),
            'recent_orders': OrderSerializer(
                Order.objects.filter(created_at__gte=thirty_days_ago)[:10], many=True
            ).data
        }
        
        return Response(stats)


class ReturnRequestViewSet(viewsets.ModelViewSet):
    """
    Return Requests management endpoint
    - Normal user: केवल अपनी return requests देख/बना सकता है
    - Staff/Admin: सब देख और update कर सकता है
    """
    serializer_class = ReturnRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        - Staff/Admin: सभी return requests
        - Normal user: सिर्फ अपनी requests
        """
        queryset = ReturnRequest.objects.select_related(
            'order__user',
            'order__address',
            'order_item__product',
            'user'
        ).prefetch_related('order__items')

        if self.request.user.is_staff:
            return queryset.all()

        return queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Create होने पर user को request.user से सेट करो
        (frontend से user फील्ड नहीं भेजना चाहिए)
        """
        serializer.save(user=self.request.user)

    def perform_update(self, serializer):
        """
        Update पर भी user को change नहीं होने देना
        """
        if 'user' in serializer.validated_data:
            raise PermissionDenied("User field cannot be modified")
        super().perform_update(serializer)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAdminUser])
    def update_status(self, request, pk=None):
        """
        Admin action: Return request का status अपडेट करना
        Allowed actions: APPROVED, REJECTED, PROCESSING, COMPLETED
        """
        return_request = self.get_object()
        order = return_request.order

        action = request.data.get('status')
        remarks = request.data.get('remarks', '').strip()

        if not action:
            raise ValidationError({"status": "This field is required."})

        valid_statuses = dict(ReturnRequest.RETURN_STATUS_CHOICES).keys()
        if action not in valid_statuses:
            raise ValidationError({"status": f"Invalid status. Allowed: {', '.join(valid_statuses)}"})

        # Status change logic
        if action == 'COMPLETED':
            if not return_request.refund_amount:
                raise ValidationError("Refund amount must be set before completing return")

            # TODO: यहाँ actual refund processing logic आएगा (Stripe/Razorpay आदि)
            return_request.refunded_at = timezone.now()
            order.payment_status = 'REFUNDED'
            order.status = 'RETURNED'
            order.return_status = 'COMPLETED'
            order.return_completed_at = timezone.now()

        # Common updates
        return_request.status = action
        return_request.admin_remarks = remarks
        return_request.save(update_fields=['status', 'admin_remarks', 'refunded_at'])

        order.return_status = action
        order.save(update_fields=['return_status', 'status', 'payment_status', 'return_completed_at'])

        return Response({
            "detail": f"Return request status updated to {action}",
            "current_status": return_request.status,
            "order_return_status": order.return_status,
            "refunded_at": return_request.refunded_at,
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """
        Create return request (user authenticated होना चाहिए)
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Users list (admin only) - Read only for security
    """
    queryset = CustomUser.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        """
        Admin ko sab users dikhao, search/filter support ke liye
        """
        queryset = CustomUser.objects.all().order_by('-date_joined')
        # Optional: search by username/email
        username = self.request.query_params.get('username')
        if username:
            queryset = queryset.filter(username__icontains=username)
        return queryset

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "User registered successfully",
                "user": {
                    "username": user.username,
                    "email": user.email,
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = CurrentUserSerializer(request.user)
        return Response(serializer.data)

class HealthCheckView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            "status": "ok",
            "message": "Server is healthy 🚀"
        }, status=status.HTTP_200_OK)