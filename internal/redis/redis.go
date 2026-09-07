package redis

import (
	"context"
	"log"
	"os"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type RedisService struct {
	Client *redis.Client
}

func InitRedis() *RedisService {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = os.Getenv("REDIS_ADDR")
	}
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	opt, err := redis.ParseURL(redisURL)
	var client *redis.Client
	if err != nil {
		// Fallback to standard address parsing
		client = redis.NewClient(&redis.Options{
			Addr:     redisURL,
			Password: "",
			DB:       0,
		})
	} else {
		client = redis.NewClient(opt)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis connection ping failed (%v). Running without Redis Pub/Sub cluster.\n", err)
	} else {
		log.Println("Successfully connected to Redis server for Pub/Sub message routing!")
	}

	return &RedisService{Client: client}
}

func (r *RedisService) PublishMessage(ctx context.Context, channel string, payload []byte) error {
	if r == nil || r.Client == nil {
		return nil
	}
	return r.Client.Publish(ctx, channel, payload).Err()
}

func (r *RedisService) SubscribeChannel(ctx context.Context, channel string) *redis.PubSub {
	if r == nil || r.Client == nil {
		return nil
	}
	return r.Client.Subscribe(ctx, channel)
}
