# run_tests.py
import pytest
import sys

def main():
    print("🚀 Running all tests...\n")
    # Run pytest on the 'test' folder
    exit_code = pytest.main(["-v", "test/"])
    if exit_code == 0:
        print("\n✅ All tests passed successfully!")
    else:
        print("\n❌ Some tests failed. Check above for details.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
