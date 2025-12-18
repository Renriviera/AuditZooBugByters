class NPDCase04:
    def __init__(self, value):
        self.value = value
    
    def get_value(self):
        return self.value.attr

def case04_inner_call(obj):
    return obj.get_value()

def case04_middle_call(obj):
    return case04_inner_call(obj)

def case04_main():
    obj = NPDCase04(None)
    return case04_middle_call(obj)


if __name__ == "__main__":
    case04_main()