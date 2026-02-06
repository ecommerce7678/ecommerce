from django.db import models, transaction
from django.contrib.auth.models import AbstractUser
from django.utils.text import slugify
from decimal import Decimal
from django.utils import timezone
from django.core.exceptions import ValidationError


class CustomUser(AbstractUser):
    phone = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return self.username

class Address(models.Model):
    user = models.ForeignKey(
        'CustomUser',
        on_delete=models.CASCADE,
        related_name='addresses'
    )
    full_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    pincode = models.CharField(max_length=10)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    address_line = models.TextField()
    is_default = models.BooleanField(
        default=False,
        verbose_name="Default Address",
        help_text="Mark this as your default delivery address"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # unique_together हटा दिया गया — अब एक user के कई non-default addresses हो सकते हैं
        verbose_name = "Address"
        verbose_name_plural = "Addresses"
        ordering = ['-is_default', '-created_at', '-updated_at']
        indexes = [
            models.Index(fields=['user', 'is_default']),
            models.Index(fields=['user', 'created_at']),
        ]

    def clean(self):
        """Basic validation before save"""
        if not self.full_name.strip():
            raise ValidationError({"full_name": "Full name cannot be empty."})
        
        if not self.phone.strip():
            raise ValidationError({"phone": "Phone number is required."})
        
        pin = self.pincode.strip()
        if not pin or len(pin) < 6:
            raise ValidationError({"pincode": "Pincode must be at least 6 characters."})
        
        if not self.city.strip():
            raise ValidationError({"city": "City is required."})
        
        if not self.state.strip():
            raise ValidationError({"state": "State is required."})
        
        if not self.address_line.strip():
            raise ValidationError({"address_line": "Address line cannot be empty."})

    def save(self, *args, **kwargs):
        # Agar yeh address default ban raha hai
        if self.is_default:
            # Purane default addresses ko false kar do (current wala chhod ke)
            Address.objects.filter(
                user=self.user,
                is_default=True
            ).exclude(pk=self.pk if self.pk else None).update(is_default=False)

        # Pehli baar save ho raha hai aur koi default nahi hai → ise default bana do
        elif not self.pk and not Address.objects.filter(user=self.user, is_default=True).exists():
            self.is_default = True

        super().save(*args, **kwargs)

    def __str__(self):
        default_mark = " (Default)" if self.is_default else ""
        return f"{self.full_name} - {self.city}, {self.pincode}{default_mark}"

    @property
    def short(self):
        """Short version for dropdowns / checkout summary"""
        line = self.address_line[:35]
        if len(self.address_line) > 35:
            line += "..."
        return f"{line}, {self.city} - {self.pincode}"

    @property
    def full_address(self):
        """Complete formatted address (useful in emails, invoices, etc.)"""
        parts = [
            self.full_name,
            self.address_line,
            f"{self.city}, {self.state} - {self.pincode}",
            f"Phone: {self.phone}",
        ]
        return "\n".join(filter(None, parts))

    def make_default(self):
        """Explicit method to set this address as default"""
        if not self.is_default:
            self.is_default = True
            self.save()  # save() method khud purana default hata dega

class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=120, unique=True, blank=True)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='children')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    image = models.URLField(max_length=500, blank=True, null=True)

    class Meta:
        verbose_name_plural = "Categories"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Product(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discount_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    stock = models.PositiveIntegerField(default=0)
    image = models.URLField(max_length=500, blank=True, null=True)
    return_window_days = models.PositiveIntegerField(
        default=10,
        verbose_name="Return Window (days)",
        help_text="Number of days customer can return this product after delivery (0 = no return allowed)",
    )
    shipping_charge = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        verbose_name="Shipping / Delivery Charge",
        help_text="0 = Free delivery for this product"
    )
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def get_display_price(self):
        return self.discount_price or self.price

    def __str__(self):
        return self.name


class CartItem(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='cart_items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'product')

    def __str__(self):
        return f"{self.product.name} x {self.quantity}"


class Coupon(models.Model):
    code = models.CharField(max_length=20, unique=True)

    discount_percent = models.PositiveIntegerField(default=0)

    discount_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0
    )  # fixed amount option

    discount_type = models.CharField(
        max_length=10,
        choices=(('PERCENT', 'Percentage'), ('AMOUNT', 'Fixed Amount')),
        default='PERCENT'
    )

    min_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    max_uses = models.PositiveIntegerField(default=0)  # 0 = unlimited
    uses_count = models.PositiveIntegerField(default=0)

    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()

    active = models.BooleanField(default=True)

    used_by = models.ManyToManyField(
        CustomUser,
        blank=True,
        related_name='used_coupons'
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def calculate_discount(self, order_total):
        """
        Calculate discount based on type and cap at max 50% of order total
        """
        if self.discount_type == 'PERCENT':
            discount = (order_total * self.discount_percent) / 100
        else:
            discount = self.discount_amount

        # Max discount limit (50% of order total)
        max_discount = order_total * Decimal("0.5")

        return min(discount, max_discount)

    def can_use(self, user, order_total=Decimal('0.00')):
        """
        Check if coupon can be applied for given user and subtotal
        Returns: (bool, message)
        """
        now = timezone.now()

        # Check if coupon is active
        if not self.active:
            return False, "Coupon is inactive"

        # Check validity date range
        if self.valid_from > now or self.valid_to < now:
            return False, "Coupon expired"

        # Check max usage limit
        if self.max_uses > 0 and self.uses_count >= self.max_uses:
            return False, "Coupon usage limit reached"

        # Check if user already used this coupon
        if user and self.used_by.filter(id=user.id).exists():
            return False, "You have already used this coupon"

        # Minimum order amount check (VERY IMPORTANT)
        if self.min_amount > 0 and order_total < self.min_amount:
            return False, f"Minimum order amount ₹{self.min_amount} required"

        # If all checks passed
        return True, "Coupon is valid"

    def __str__(self):
        return self.code


class Order(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('CONFIRMED', 'Confirmed'),
        ('PROCESSING', 'Processing'),
        ('SHIPPED', 'Shipped'),
        ('DELIVERED', 'Delivered'),
        ('CANCELLED', 'Cancelled'),
        ('RETURNED', 'Returned'),
    )
    
    PAYMENT_METHOD_CHOICES = (
        ('COD', 'Cash on Delivery'),
        ('ONLINE', 'Online Payment'),
        ('WALLET', 'Wallet'),
    )
    
    PAYMENT_STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('PAID', 'Paid'),
        ('FAILED', 'Failed'),
        ('REFUNDED', 'Refunded'),
    )
    
    RETURN_STATUS_CHOICES = (
        ('NONE', 'No Request'),
        ('REQUESTED', 'Requested'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
    )

    user = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, related_name='orders')
    order_number = models.CharField(max_length=50, unique=True, editable=False)
    address = models.ForeignKey('Address', on_delete=models.PROTECT, related_name='orders')
    razorpay_order_id = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        unique=True,           # optional लेकिन अच्छा रहेगा
        help_text="Razorpay से मिला Order ID"
    )
    
    # Financial fields
    subtotal = models.DecimalField(max_digits=12, decimal_places=2)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    shipping = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    final_amount = models.DecimalField(max_digits=12, decimal_places=2)
    
    # Status fields
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES, default='COD')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='PENDING')
    
    # Return/Refund fields
    return_requested = models.BooleanField(default=False)
    return_status = models.CharField(max_length=20, choices=RETURN_STATUS_CHOICES, default='NONE')
    return_reason = models.TextField(blank=True, null=True)
    return_requested_at = models.DateTimeField(null=True, blank=True)
    return_approved_at = models.DateTimeField(null=True, blank=True)
    return_completed_at = models.DateTimeField(null=True, blank=True)
    admin_remarks = models.TextField(blank=True, null=True)
    
    # Tracking
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Order"
        verbose_name_plural = "Orders"

    def save(self, *args, **kwargs):
        # Generate order number only once (on create)
        if not self.order_number:
            self.order_number = f"ORD-{timezone.now().strftime('%Y%m%d%H%M%S')}-{self.user_id or '0'}"

        # Handle DELIVERED status change
        if self.status == 'DELIVERED':
            # Only set delivered_at if it's not already set
            # and this is either a new order created directly as DELIVERED
            # or an update from non-DELIVERED status
            if not self.delivered_at:
                if self.pk:  # existing order → check previous status
                    previous = Order.objects.filter(pk=self.pk).only('status').first()
                    if previous and previous.status != 'DELIVERED':
                        self.delivered_at = timezone.now()
                else:  # new order created directly as DELIVERED (rare, mostly admin)
                    self.delivered_at = timezone.now()

        # Auto-update payment status for COD when delivered
        if self.status == 'DELIVERED' and self.payment_method == 'COD':
            if self.payment_status != 'PAID':
                self.payment_status = 'PAID'

        super().save(*args, **kwargs)

    def get_status_display(self):
        return dict(self.STATUS_CHOICES).get(self.status, self.status)

    def get_payment_status_display(self):
        return dict(self.PAYMENT_STATUS_CHOICES).get(self.payment_status, self.payment_status)

    def __str__(self):
        return f"{self.order_number} - {self.user.username if self.user else 'Guest'}"

    @property
    def can_be_returned(self):
        """Frontend ke liye helper property (serializer mein bhi use hota hai)"""
        if self.status != 'DELIVERED' or not self.delivered_at:
            return False
        
        # Assuming min return days from items (ya fixed 7/10/15 days)
        # Yeh logic aapke serializer mein already hai, yaha sirf reference
        return True  # implement full logic as per your requirement


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT, related_name='order_items')
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)  # snapshot price
    subtotal = models.DecimalField(max_digits=12, decimal_places=2, editable=False)

    def save(self, *args, **kwargs):
        self.subtotal = self.price * self.quantity
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.product.name} x {self.quantity}"


class ReturnRequest(models.Model):
    RETURN_STATUS_CHOICES = (
        ('REQUESTED', 'Requested'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
    )

    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='return_requests')
    order_item = models.ForeignKey(OrderItem, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)  # partial return
    reason = models.TextField()
    description = models.TextField(blank=True, null=True)
    images = models.JSONField(default=list, blank=True, null=True)  # list of image URLs
    
    status = models.CharField(max_length=20, choices=RETURN_STATUS_CHOICES, default='REQUESTED')
    admin_remarks = models.TextField(blank=True, null=True)
    
    requested_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Refund details
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    refunded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('order', 'order_item', 'status')

    def __str__(self):
        return f"Return {self.id} for Order {self.order.order_number}"


class WishlistItem(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='wishlist_items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'product')

    def __str__(self):
        return f"{self.user.username} - {self.product.name}"