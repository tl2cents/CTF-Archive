def check_sat_pell(x, y, n):
    if x^2 - n * y ^ 2 == 1:
        return True
    else:
        return False


def solve_pell_equation(n, nums_of_solutions):
    # x^2 - n * y ^ 2 = 1
    nth_continue_fraction = continued_fraction(sqrt(n))
    count = 0
    i = 0
    while count < nums_of_solutions:
        temp_numerator = nth_continue_fraction.numerator(i)
        temp_denominator = nth_continue_fraction.denominator(i)
        if check_sat_pell(temp_numerator, temp_denominator, n):
            print(f"{i} th solution is ", temp_numerator, temp_denominator)
            count += 1
        i += 1