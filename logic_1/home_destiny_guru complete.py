print("Welcome to Home Destiny Guru!!!")

# Hardcoding these correct values to represent the user's credentials
correct_username = "rickc137"
correct_password = "noobnoob"
computer_weather = 76
#give user the option to try again for the first time
user_wants_to_try_again = 1


# Prompting the user for their username and password
username = input("Enter your username: ")
password = input("Enter your password: ")
if username == correct_username and password == correct_password:
    print("Access granted! Welcome, " + username + "!")
else:
    print("Access denied! Incorrect username or password.")

while username != correct_username or password != correct_password:
    #ask the user again for their username
    print("At least one of your credentials is incorrect. Please try again.")
    username = input("Enter your username: ")
    password = input("thank you, please enter your password: ")
  
 
print("Welcome,"+ username + "!") 

#try again
while user_wants_to_try_again:
    raining = int(input("is it raining? press 1 for yes, 0 for no: "))
    at_home = int(input("where are you? press 1 for home. 0 for work." ))

    if raining and at_home:
        print("Stay home")
    elif raining and not at_home:
        print("Stay at work")
    elif not raining and at_home:
        print("Go to work")
    elif not raining and not at_home:
        print("Go home")   

    print("Thank you for using Home Destiny Guru! Have a great day!")


    user_response = input("Do you want to try again? Press y/n: ")
    

    while user_response != "y" and user_response != "n":    
            user_response =input ("Invalid input. Please enter 'y' to try again or 'n' to exit: ")
    if user_response == "y":
        user_wants_to_try_again = 1
    elif user_response == "n":
        user_wants_to_try_again = 0

print("Bye! Thank you for using Home Destiny Guru!")
    
    
    
# You can add code here to restart the program if needed

#user_location_as_string = input("Location? press 1 for home. 2 for work." ) 
#user_location_as_int = int(user_location_as_string)

#raining = int(input("Is it raining? press 1 for yes, 2 for no: "))  


#if raining and user_location_as_int == 1:
    #print("Stay home")
#elif raining and user_location_as_int == 2:
    #print("Stay at work")

#if raining.lower() == "yes" and user_location_as_int == 1:
    #print("Stay home")
#elif raining.lower() == "yes" and user_location.lower() == "work": 
    #print("Stay at work")
    