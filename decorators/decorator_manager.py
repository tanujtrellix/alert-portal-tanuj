# Decorator manager to apply decorators to function
class DecoratorManager:
    def __init__(self, *decorators):
        self.decorators = decorators

    def apply_decorators(self, func):
        for decorator in reversed(self.decorators):
            func = decorator(func)
        return func
