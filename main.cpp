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

//???
string mitigateAddState(string sql){
    //throw exception("Not implemented");
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
string mitigateValid(string sql){

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
}

//???
void testUnion(string sql){
    //throw exception("Not implemented");
}

//???
void testTautology(string sql){

}

//Returns a query with the username and password. Tests if they are valid.
void testValid(string sql){

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

    testValid(sql);
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

    testValid(sql);
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

    testValid(sql);
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

