package com.tastytown.backend.service.impl;

import java.util.NoSuchElementException;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.tastytown.backend.dto.CartItemRequestDTO;
import com.tastytown.backend.dto.CartResponseDTO;
import com.tastytown.backend.entity.Cart;
import com.tastytown.backend.entity.CartItem;
import com.tastytown.backend.entity.Food;
import com.tastytown.backend.entity.User;
import com.tastytown.backend.helper.UserServiceHelper;
import com.tastytown.backend.mapper.CartMapper;
import com.tastytown.backend.repository.CartRepository;
import com.tastytown.backend.repository.FoodRepository;
import com.tastytown.backend.repository.UserRepository;
import com.tastytown.backend.service.ICartService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CartServiceImpl implements ICartService {
    private final CartRepository cartRepository;
    private final UserRepository userRepository;
    private final FoodRepository foodRepository;
    private final UserServiceHelper userServiceHelper;

    @Override
    public CartResponseDTO addItemToCart(String userId, CartItemRequestDTO cartItemRequestDTO) {
        var user = userServiceHelper.getUserById(userId);
        var cart = getOrCreateCartForUser(user);
        var food = getFoodById(cartItemRequestDTO.foodId());

        // check if item alreay exists in the cart
        Optional<CartItem> existingCartItemOpt = cart.getItems().stream()
                .filter(item -> item.getFood().getFoodId().equals(food.getFoodId()))
                .findFirst();

        if (existingCartItemOpt.isPresent()) {
            // update quantity if cart item is present
            CartItem existingCartItem = existingCartItemOpt.get();
            existingCartItem.setQuantity(existingCartItem.getQuantity() + cartItemRequestDTO.quantity());
        } else {
            // create a new cart item if not exist
            CartItem newCartItem = CartItem.builder()
                    .cart(cart)
                    .food(food)
                    .quantity(cartItemRequestDTO.quantity())
                    .build();
            cart.getItems().add(newCartItem);
        }

        var savedCart = cartRepository.save(cart);

        return CartMapper.convertToCartResponseDTO(savedCart);
    }

    @Override
    public CartResponseDTO getCartByUserId(String userId) {
        var user = userServiceHelper.getUserById(userId);
        var cartOfUser = getOrCreateCartForUser(user);

        return CartMapper.convertToCartResponseDTO(cartOfUser);
    }

    @Override
    public CartResponseDTO updateItemQuantity(String userId, CartItemRequestDTO cartItemRequestDTO) {
        var user = userServiceHelper.getUserById(userId);
        var cart = getOrCreateCartForUser(user);

        var cartItem = getMatchedCartItemOfAnUser(cart, cartItemRequestDTO.foodId());

        if (cartItemRequestDTO.quantity() <= 0) {
            // remove the item
            cart.getItems().remove(cartItem);
        } else {
            cartItem.setQuantity(cartItemRequestDTO.quantity());
        }

        var savedCart = cartRepository.save(cart);
        return CartMapper.convertToCartResponseDTO(savedCart);
    }

    @Override
    public CartResponseDTO removeItemFromCart(String userId, String foodId) {
        var user = userServiceHelper.getUserById(userId);
        var cart = getOrCreateCartForUser(user);
        var cartItem = getMatchedCartItemOfAnUser(cart, foodId);

        cart.getItems().remove(cartItem);
        var savedCart = cartRepository.save(cart);

        return CartMapper.convertToCartResponseDTO(savedCart);
    }

    @Override
    public void clearCartItems(String userId) {
        var user = userServiceHelper.getUserById(userId);
        cartRepository.deleteByUser(user);
    }

    // helper methods
    private CartItem getMatchedCartItemOfAnUser(Cart cart, String foodId) {
        return cart.getItems().stream()
                .filter(item -> item.getFood().getFoodId().equals(foodId))
                .findFirst().orElseThrow(() -> new NoSuchElementException("Food Not Found In the Cart"));
    }


    private Cart getOrCreateCartForUser(User user) {
        return cartRepository.findByUser(user).orElseGet(
                () -> {
                    var newCart = new Cart();
                    newCart.setUser(user);
                    return cartRepository.save(newCart);
                });
    }

    private Food getFoodById(String foodId) {
        return foodRepository.findById(foodId)
                .orElseThrow(() -> new NoSuchElementException("Food not found with id " + foodId));
    }
}
