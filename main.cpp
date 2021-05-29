#include <iostream>
#include <sstream>
#include <stdio.h>
#include <ctype.h>

using namespace std;

std::string line;

//???
string mitigateCommandInjection(string sql){
    //throw exception("Not implemented");
}

//???
string mitigateComment(string sql){
    //throw exception("Not implemented");
}

// In this scenario where we are only asking for a username and password,
// that information will not get passed into the operating system command 
// interpreter, and therefore an additional statement attack could not occur.
// However, if we were to send this info to the system, the best way to mitigate
// an additional statement attack would be to eliminate semicolons, which is what this
// function does.
string mitigateAddState(string sql){
    //throw exception("Not implemented");
    for(int i = 0; i < sql.length(); i++){
        if(sql[i] == 59){    //59 is the ASCII code for ';'
            sql[i] = ' ';
        }
    }
    return sql;
}

//???
string mitigateUnion(string sql){
    //throw exception("Not implemented");
    //Is there union
    string cleanedScript = "";

    /*******
     * SET Operator Mitigation
     * Conditions:
     * If this string contains 'UNION'
     * If the sql string contains 'INTERSECT'
     * If the sql string contains 'MINUS'
     * If the sql string contains too many spaces
     */
    if (sql == "UNION"){
        return "invalid password";
    }
    return cleanedScript;
}

//???
string mitigateTautology(string sql){

}

//Returns a query with the username and password. Tests if they are valid.
//Not really sure what to do with this one, so with this I'm just changing the
//invalid characters into spaces.
string mitigateValid(string sql){
    for (int i = 0; i < sql.length(); i++){
        if (sql[i] >= 65 && sql[i] <= 90 || //uppercase letters
        sql[i] >= 97 && sql[i] <= 122 || //lowercase letters
        sql[i] >= 48 && sql[i] <= 57 || //numbers 
        sql[i] == 95) //underscore
        {
            continue;
        }
        else {
            sql[i] = ' ';
        }
    }
}

//???
void testCommandInjection(string sql){
    //throw exception("Not implemented");
}

//???
void testComment(string sql){
    //throw exception("Not implemented");
}

//???
void testAddState(string sql){
    //throw exception("Not implemented");
    for(int i = 0; i < sql.length(); i++){
        if(sql[i] == 59){    //59 is the ASCII code for ';'
            cout << "Possible Additional Statement Attack";
        }
    }
    
}

//???
void testUnion(string sql){
    //throw exception("Not implemented");
}

//???
void testTautology(string sql){

}


//sub-function of testValid
bool testValidInput(string input){
    bool validInput = true;
    for (int i = 0; i < input.length(); i++){
        if (input[i] >= 65 && input[i] <= 90 || //uppercase letters
        input[i] >= 97 && input[i] <= 122 || //lowercase letters
        input[i] >= 48 && input[i] <= 57 || //numbers 
        input[i] == 95) //underscore
        {
            continue;
        }
        else {
            validInput = false;
            break;
        }
    }
    return validInput;
}

//Returns a query with the username and password. Tests if they are valid.
//Assignment says "Generate a set of cases (one for each member of your team) that 
//represent valid input where the username and the password consist of letters, numbers, 
//and underscores." Based on this, will check to see if username and password consist of 
//letters, numbers, and underscore, and will output whether or not it is valid.
void testValid(string username, string password){
    bool validUsername = testValidInput(username);
    bool validPassword = testValidInput(password);

    if(validUsername)
        cout << "The username has a valid input" << endl;
    else
        cout << "The username does not have a valid input" << endl;
    if(validPassword)
        cout << "The password has a valid input" << endl;
    else
        cout << "The password does not have a valid input" << endl;
}

//Provides a strong mitigation against all five attacks (Tautology, Union, AddState, Comment, Command Injection)
string genQueryStrong(const string& username, const string& password){
    stringstream s = stringstream("");

    //Sanitize these against these 6 tests

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password="
      << password
      << " and username="
      << username
      << "\";";

    string sql = s.str();
    sql = mitigateValid(sql);
    sql = mitigateTautology(sql);
    sql = mitigateUnion(sql);
    sql = mitigateAddState(sql);
    sql = mitigateComment(sql);
    sql = mitigateCommandInjection(sql);

    testValid(username, password);
    testTautology(sql);
    testUnion(sql);
    testAddState(sql);
    testComment(sql);
    testCommandInjection(sql);

    return sql;
}

//Provides a weak mitigation against all four attacks (Tautology, Union, AddState, Comment)
string genQueryWeak(const string& username, const string& password){
    stringstream s = stringstream("");

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password="
      << password
      << " and username="
      << username
      << "\";";

    //Sanitize these against these 5 tests

    string sql = s.str();
    sql = mitigateValid(sql);
    sql = mitigateTautology(sql);
    sql = mitigateUnion(sql);
    sql = mitigateAddState(sql);
    sql = mitigateComment(sql);

    testValid(username, password);
    testTautology(sql);
    testUnion(sql);
    testAddState(sql);
    testComment(sql);

    return sql;
}

//Returns a single string (SQL) represents the query used to determine if a user is authenticated on a given system
string genQuery(const string& username, const string& password){
    stringstream s = stringstream("");

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password="
      << password
      << " and username="
      << username
      << "\";";

    string sql = s.str();

    testValid(username, password);
    testTautology(sql);
    testUnion(sql);
    testAddState(sql);
    testComment(sql);

    return sql;
}

int main() {
    string in_username;
    string in_password;



    cout << "Please login.\n";
    cout << "Username: ";
    getline(cin, in_username);
    cout << "Password: ";
    getline(cin,in_password);

    cout << genQuery(in_username, in_password) << endl;
    return 0;
}

