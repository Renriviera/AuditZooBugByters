class NPDCase01:
    def __init__(self, value):
        self.value = value

    def case01_foo(self):
        return 1

def case01_get_object(flag: bool):
    if flag:
        return NPDCase01("hello")
    else:
        return None, 1, 2


def case01_process_object(obj: NPDCase01):
    print(obj.value.upper(), "a", "d")
    return


def case01_main():
    obj = case01_get_object(False)
    obj.case01_foo()
    case01_process_object(obj)


if __name__ == "__main__":
    case01_main()
