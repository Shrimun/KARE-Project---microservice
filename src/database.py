"""MongoDB database connection and utilities."""

from __future__ import annotations

import logging
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ServerSelectionTimeoutError

from src.config import get_settings

logger = logging.getLogger(__name__)

# Global database client (initialized on startup)
_db_client: Optional[AsyncIOMotorClient] = None
_database: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongodb() -> None:
    """Establish connection to MongoDB."""
    global _db_client, _database
    
    settings = get_settings()
    
    try:
        logger.info(f"Connecting to MongoDB at {settings.mongodb_uri}")
        _db_client = AsyncIOMotorClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=5000,
            maxPoolSize=10,
            minPoolSize=1,
        )
        
        # Verify connection
        await _db_client.admin.command('ping')
        
        _database = _db_client[settings.mongodb_database]
        logger.info(f"Successfully connected to MongoDB database: {settings.mongodb_database}")
        
        # Create indexes
        await create_indexes()
        
    except ServerSelectionTimeoutError as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise RuntimeError(f"Could not connect to MongoDB at {settings.mongodb_uri}") from e
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB: {e}")
        raise


async def close_mongodb_connection() -> None:
    """Close MongoDB connection."""
    global _db_client
    
    if _db_client:
        logger.info("Closing MongoDB connection")
        _db_client.close()
        _db_client = None


async def create_indexes() -> None:
    """Create database indexes for optimal query performance."""
    if _database is None:
        raise RuntimeError("Database not initialized")
    
    users_collection = _database["users"]
    sessions_collection = _database["sessions"]
    
    # Create unique index on email
    await users_collection.create_index("email", unique=True)
    
    # Create index on session token
    await sessions_collection.create_index("token", unique=True)
    
    # Create TTL index on session expiry (auto-delete expired sessions)
    await sessions_collection.create_index("expires_at", expireAfterSeconds=0)
    
    logger.info("Database indexes created successfully")


def get_database() -> AsyncIOMotorDatabase:
    """Get the database instance."""
    if _database is None:
        raise RuntimeError("Database not initialized. Call connect_to_mongodb() first.")
    return _database
