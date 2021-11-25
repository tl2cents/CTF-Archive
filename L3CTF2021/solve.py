#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
python解方程
"""
 
from scipy.optimize import fsolve
 
def solve_function(unsolved_value):
    x,y,z=unsolved_value[0],unsolved_value[1],unsolved_value[2]
    return [
        0.05*(x+y+z)-x,
        0.475*x+0.05*y+0.9*z-y,
        x+y+z-1,
    ]
 
solved=fsolve(solve_function,[0, 0, 0])
print(solved)
 
 
print("Program done!")
 
"""
运行结果：
[-1.  3.  5.]
Program done!
"""