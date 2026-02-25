package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

// handler receives user input and passes it to helper functions.
func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	runQuery(id)

	cmd := r.URL.Query().Get("cmd")
	executeCommand(cmd)
}

// runQuery takes an untrusted ID and executes a SQL query.
func runQuery(userID string) {
	db, _ := sql.Open("postgres", "")
	db.Exec("SELECT * FROM users WHERE id=" + userID)
}

// executeCommand takes an untrusted command and runs it.
func executeCommand(command string) {
	exec.Command("sh", "-c", command)
}

// safeFunc does not contain any sinks.
func safeFunc(data string) string {
	return "processed: " + data
}
