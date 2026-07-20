# #function without parameters
# def greet_user():
#     print("say hello")
#     print("-------------")
#     print("-------------")
#     print("-----------!--")
#     print("-------------")
#     print("------------!-")
#     print("------------!-")
#     print("hope you have a nice day")
#funtion with parameters

def greet_user(username):
    print("Hello", username + "!")
    print("-------------")
    print("-------------")
    print("-----------!--")
    print("-------------")
    print("------------!-")
    print("------------!-")
    print("hope you have a nice day")



name = input("Enter your name :")
greet_user(name)

greet_user()
#username = input("Enter your name: ")
#greet_user(username)    
#calling the function with an argument