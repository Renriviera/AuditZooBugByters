def case05_get_list():
    return [None] * 5

def case05_inner(lst):
    return lst[2].attr

def case05_middle(lst):
    return case05_inner(lst)

def case05_use_list():
    lst = case05_get_list()
    return case05_middle(lst)


if __name__ == "__main__":
    case05_use_list()
