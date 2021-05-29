#include <iostream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <utility>

using namespace std;

//Is the character a space
bool isSpace(char c){
    return (c == ' ');
}

//Is the character alphanumeric
bool isAlphaNumericUnderscore(char c){
    return (c >= 65 && c <= 90 || //uppercase letters
            c >= 97 && c <= 122 || //lowercase letters
            c >= 48 && c <= 57 || //numbers
            c == 95);
}

//Gets the next word at index
string getWord(string s, int index){
    stringstream word = stringstream("");

    for (int i = index; i < s.length(); ++i) {
        if (isSpace(s[i])){
            return word.str();
        } else {
            word << s[i];
        }
    }

    return word.str();
}

//Checks if there is a comment starting at this index. Pass the first character of the comment
bool isComment(string s, int index){
    if (s.length() <= index+1){
        return false;
    } else {
        return ((s[index] == '-') && (s[index + 1] == '-'));
    }
}

//Checks if it is a quote. SQL only accepts single quotes, we filter from both just in case a dialect of SQL
// uses it for some strange reason.
bool isQuote(char c){
    return ((c == '\'') || (c == '\"'));
}

//Checks if it is a semicolon
bool isSemicolon(char c){
    return (c == ';');
}

//Gets the lower case version of the word
string getLowerCase(string word){
    transform(word.begin(), word.end(), word.begin(), std::tolower);
    return word;
}

//Tests if a comment is present
void testComment(string sql){
    string comment ="--";
    long found = sql.find(comment);
    if (found != string::npos)
    {
        cout << "\tThere is a comment in this string, we have failed mitigation \n";
    }
    else
    {
        cout<< "\tSuccess: No Comments\n";
    }
}

//Tests if an additional statement may be present
void testAddState(string sql){
    bool success = true;

    for(int i = 0; i < sql.length(); i++){
        if(sql[i] == 59){    //59 is the ASCII code for ';'
            cout << "\tERROR: Possible Additional Statement Attack\n";
            success = false;
        }
    }

    if (success){
        cout << "\tSuccess: No Additional Statement Attack\n";
    }
}

//Tests if union is present
void testUnion(string sql){
    string lower = getLowerCase(std::move(sql));
    string comment ="union";
    long found = lower.find(comment);
    if (found != string::npos)
    {
        cout << "\tERROR: There is a possible union statement in the query \n";
    }
    else
    {
        cout<< "\tSuccess: No Union Statement\n";
    }
}

//Tests if there may be a tautology attack present
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

//Performs strong mitigation against attacks for the specific string, only accepting valid input
string strongMitigation(const string& input){
    stringstream sBuilder = stringstream("");

    for (char i : input) {
        if (isAlphaNumericUnderscore(i)){
            sBuilder << i;
        }
    }

    return sBuilder.str();
}

//Performs weak mitigation against attacks for the specific string, filtering from a "blocklist"
string weakMitigation(const string& input){
    stringstream sBuilder = stringstream("");

    for (int i = 0; i < input.length(); ++i) {
        if (isComment(input, i)) { //Protect against Comment Attack
            continue;
        } else if (isQuote(input[i])){ // Protect against Tautology Attack
            continue;
        } else if (isSemicolon(input[i])){ // Protect against Additional Statement
            continue;
        } else if (isSpace(input[i])){
            if (getLowerCase(getWord(input, i + 1)) == "union"){ //Protect against Union Attack
                i += 5; //Skip 5
                continue;
            }
        } else {
            sBuilder << input[i];
        }
    }

    return sBuilder.str();
}

//Provides a strong mitigation against all five attacks (Tautology, Union, AddState, Comment, Command Injection)
string genQueryStrong(const string& username, const string& password){
    cout << endl << "getQueryStrong() called" << endl;
    cout << "Strong Mitigation against attacks. In other words, only accepts valid input.\n\n";

    stringstream s = stringstream("");

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password=\""
      << strongMitigation(username)
      << "\" and username=\""
      << strongMitigation(password)
      << "\";";

    return s.str();
}

//Provides a weak mitigation against all four attacks (Tautology, Union, AddState, Comment)
string genQueryWeak(const string& username, const string& password){
    cout << endl << "genQueryWeak() called" << endl;
    cout << "Weak Mitigation against attacks. In other words, goes off of a blocklist.\n\n";
    stringstream s = stringstream("");

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password=\""
      << weakMitigation(username)
      << "\" and username=\""
      << weakMitigation(password)
      << "\";";

    return s.str();
}

//Returns a single string (SQL) represents the query used to determine if a user is authenticated on a given system
string genQuery(const string& username, const string& password){
    //system("Color 0A");
    cout << endl << "genQuery() called" << endl;
    //system("Color 07");
    cout << "Generates SQL and tests it against the various attacks in the lab\n\n";

    stringstream s = stringstream("");

    s << "SELECT authenticate\n"
         "FROM passwordList\n"
         "WHERE password=\""
      << password
      << "\" and username=\""
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

    cout << genQuery(in_username, in_password) << endl << endl;

    try {
        cout << genQueryWeak(in_username, in_password) << endl << endl;
    } catch (exception& e) {
        cout << e.what() << '\n';
    }

    try {
        cout << genQueryStrong(in_username, in_password) << endl << endl;
    } catch (exception& e) {
        cout << e.what() << '\n';
    }

    return 0;
}

