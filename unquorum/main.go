package main

import (
	"log"

	bolt "go.etcd.io/bbolt"
)

func main() {
	// Open the my.db data file in your current directory.
	// It will be created if it doesn't exist.
	db, err := bolt.Open("../backup/var/lib/etcd/member/snap/db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		tx.DeleteBucket([]byte("members"))
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
}
