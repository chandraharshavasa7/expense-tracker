#!/usr/bin/env python3
"""
Test script to verify backend functionality
"""

import requests
import json

BASE_URL = "http://localhost:5001"

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/api/health")
        print(f"Health check: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False

def test_register():
    """Test user registration"""
    try:
        data = {
            "name": "Test User",
            "email": "test@example.com",
            "password": "testpass123"
        }
        response = requests.post(f"{BASE_URL}/api/auth/register", json=data)
        print(f"Register test: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code in [201, 400]  # 400 if user already exists
    except Exception as e:
        print(f"Register test failed: {e}")
        return False

def test_login():
    """Test user login"""
    try:
        data = {
            "email": "test@example.com",
            "password": "testpass123"
        }
        response = requests.post(f"{BASE_URL}/api/auth/login", json=data)
        print(f"Login test: {response.status_code}")
        result = response.json()
        print(f"Response: {result}")
        
        if response.status_code == 200:
            return result.get('token')
        return None
    except Exception as e:
        print(f"Login test failed: {e}")
        return None

def test_add_expense(token):
    """Test adding expense"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        data = {
            "category": "Food & Dining",
            "amount": 25.50,
            "description": "Test expense",
            "date": "2025-07-28"
        }
        response = requests.post(f"{BASE_URL}/api/expenses", json=data, headers=headers)
        print(f"Add expense test: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 201
    except Exception as e:
        print(f"Add expense test failed: {e}")
        return False

def main():
    print("🧪 Backend API Test Suite")
    print("=========================")
    
    # Test health
    if not test_health():
        print("❌ Backend is not healthy. Please check your server.")
        return
    
    print("\n" + "="*50)
    
    # Test registration
    test_register()
    
    print("\n" + "="*50)
    
    # Test login
    token = test_login()
    if not token:
        print("❌ Login failed. Cannot test authenticated endpoints.")
        return
    
    print("\n" + "="*50)
    
    # Test add expense
    test_add_expense(token)
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    main()
