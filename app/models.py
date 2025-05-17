from app import db

class Device:
    @staticmethod
    def get_collection():
        return db.devices
    
    @classmethod
    def create(cls, device_data):
        return cls.get_collection().insert_one(device_data)
    
    @classmethod
    def find_by_id(cls, device_id):
        return cls.get_collection().find_one({'device_id': device_id})
    
    @classmethod
    def update_public_key(cls, device_id, new_public_key):
        return cls.get_collection().update_one(
            {'device_id': device_id},
            {'$set': {'public_key': new_public_key}}
        )